package cloud

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/util"
)

type Connector struct {
	baseURL     string
	apiKey      string
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	keyLabel    string
	client      *http.Client
}

func NewConnector(url string, label string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	c := Connector{verbose: verbose, trust: trust, keyLabel: label}

	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// normalizeURL allows overriding the default URL used to communicate with Venafi Cloud
func normalizeURL(url string) (normalizedURL string, err error) {
	if url == "" {
		url = apiURL
	}
	normalizedURL = util.NormalizeUrl(url)
	return normalizedURL, nil
}

func (c *Connector) SetKeyLabel(p string) {
	c.keyLabel = p
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeCloud
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

// Ping attempts to connect to the Venafi Cloud API and returns an error if it cannot
func (c *Connector) Ping() (err error) {
	return nil
}

func (c *Connector) GetKeyID(label string) (endpoint.Environment, error) {
	req := getObjectsRequest{LabelFilter: []string{label}, IncludeChain: true}
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignGetObjects, req)
	//statusCode, status, body, err := c.request("POST", urlResourceCodeSignGetObjects, nil)

	if err != nil {
		return endpoint.Environment{}, err
	}
	keyId, certs, publicKey, err := parseGetObjectsResult(statusCode, status, body, label)
	if err != nil {
		return endpoint.Environment{}, err
	}
	return endpoint.Environment{KeyID: keyId, CertificateChainData: certs, PublicKey: publicKey}, nil

}

func (c *Connector) Sign(so *endpoint.SignOption) (sig []byte, err error) {
	var signReq apiSignRequest
	switch so.Mechanism {
	case crypto.RsaPkcs, crypto.MlDsa, crypto.SlhDsa:
		hasher, _, prefix := crypto.GetHasher(so.DigestAlg)

		//Experimental SHA3/SHAKE support
		if (so.Mechanism == crypto.RsaPkcs || so.Mechanism == crypto.EcDsa) && so.DigestAlg == "shake" {
			return nil, fmt.Errorf("SHA3/SHAKE experimental support only for MlDsa or SlhDsa")
		}
		payload := []byte(so.Payload)
		if so.B64Flag {
			payload, err = crypto.DecodeBase64(string(so.Payload))
			if err != nil {
				return nil, err
			}
		}
		if err != nil {
			return nil, err
		}
		var hv []byte
		if so.DigestFlag {
			hv = append(prefix, so.Payload...)
		} else {
			hasher.Write([]byte(payload))
			hv = append(prefix, hasher.Sum(nil)...)
		}
		var mech = 0
		if so.Mechanism == crypto.EcDsa {
			mech = crypto.GetECClientMechanism(so.DigestAlg)
		} else if so.Mechanism == crypto.RsaPkcs {
			mech = crypto.GetRSAClientMechanism(so.DigestAlg)
		} else {
			mech = 0
		}
		//job := defaultClientID + "-job-" + randstr.Hex(10)
		signReq = apiSignRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: so.KeyID, ClientMechanism: mech, Mechanism: so.Mechanism, Data: crypto.EncodeBase64(hv)}

	case crypto.RsaPkcsPss, crypto.EcDsa: // RSA PSS
		payload := []byte(so.Payload)
		if so.B64Flag {
			payload, err = crypto.DecodeBase64(string(so.Payload))
			if err != nil {
				return nil, err
			}
		}

		//hasher, _, prefix := crypto.GetHasher(so.DigestAlg)
		hasher, _, _ := crypto.GetHasher(so.DigestAlg)
		hasher.Write([]byte(payload))
		//hv := append(prefix, hasher.Sum(nil)...)
		hv := hasher.Sum(nil)
		//println(base64.StdEncoding.EncodeToString(hv))

		//mech := crypto.GetPSSMechanism(so.DigestAlg)
		//signReq = apiSignRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: so.KeyID, ClientMechanism: mech.Mechanism, Mechanism: so.Mechanism, ParameterInfo: ParameterInfo{ParameterType: "PKCSPSS", MGF: mech.MGF, HashAlg: mech.HashAlg, SaltLen: mech.SaltLen}, Data: crypto.EncodeBase64(hv)}
		if so.Mechanism == crypto.EcDsa {
			mech := crypto.GetECClientMechanism(so.DigestAlg)
			signReq = apiSignRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: so.KeyID, ClientMechanism: mech, Mechanism: so.Mechanism, Data: crypto.EncodeBase64(hv)}
		} else {
			mech := crypto.GetPSSMechanism(so.DigestAlg)
			signReq = apiSignRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: so.KeyID, ClientMechanism: mech.Mechanism, Mechanism: so.Mechanism, ParameterInfo: ParameterInfo{ParameterType: "PKCSPSS", MGF: mech.MGF, HashAlg: mech.HashAlg, SaltLen: mech.SaltLen}, Data: crypto.EncodeBase64(hv)}
		}

	default:
		signReq = apiSignRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: so.KeyID, Mechanism: so.Mechanism, Data: string(so.Payload)}
	}
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignAPISign, signReq)

	if err != nil {
		return nil, err
	}

	result, err := parseSignResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	if so.RawFlag {
		return []byte(result), err
	} else {
		sig, err = crypto.EncodeASN1(result, so.Mechanism)
	}

	return

}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = endpoint.DefaultClientID
	}

	if auth.ServiceAccountClientId != "" && auth.ServiceAccountKeyFile != "" {
		result, err := processAuthData(c, urlResourceAuthorizeServiceAccount, auth)
		if err != nil {
			return err
		}
		resp := result.(OauthGetTokenResponse)
		auth.AccessToken = resp.Access_token
		c.accessToken = resp.Access_token
		log.Trace().Msgf("Successfully authenticated with service account. Access token: %s", auth.AccessToken)
		return nil
	}

	if auth.APIKey != "" {
		c.apiKey = auth.APIKey
		return nil
	}

	return fmt.Errorf("failed to authenticate: can't determine valid credentials set")
}

func (c *Connector) GetCredential(auth *endpoint.Authentication) (token string, err error) {
	return "", fmt.Errorf("operation not supported by cloud")
}

func (c *Connector) SetProject(p string) {
	panic("operation not supported for cloud")
}

func (c *Connector) GetEnvironment() (endpoint.Environment, error) {
	return c.GetKeyID(c.keyLabel)
}

func (c *Connector) GetEnvironmentKeyAlgorithm() (string, error) {
	return "", fmt.Errorf("operation not supported by cloud")
}

func (c *Connector) GetWKSPublicKeyBytes(email string) (pub []byte, err error) {
	return nil, fmt.Errorf("operation not supported by cloud")
}

func (c *Connector) SignJWT(keyID string, header string, payload string) (jwt string, err error) {
	return "", fmt.Errorf("operation not supported by cloud")
}

func (c *Connector) GetJwksX5u(cert *x509.Certificate) (string, error) {
	return "", fmt.Errorf("operation not supported by cloud")
}

func processAuthData(c *Connector, url urlResource, auth *endpoint.Authentication) (resp interface{}, err error) {
	assertion, err := generateJWT(auth)
	if err != nil {
		return resp, fmt.Errorf("failed to generate JWT assertion: %v", err)
	}
	statusCode, status, body, err := c.requestURLEncoded("POST", url, assertion)
	if err != nil {
		return resp, err
	}

	var authorize OauthGetTokenResponse

	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &authorize)
		if err != nil {
			return resp, err
		}
		resp = authorize

	} else {
		return resp, fmt.Errorf("unexpected status code on TPP Authorize. Status: %s, Details: %s", status, NewAuthenticationError(body))
	}

	return resp, nil
}

func generateJWT(auth *endpoint.Authentication) (string, error) {
	privateKeyBytes, err := os.ReadFile(auth.ServiceAccountKeyFile)
	if err != nil {
		return "", fmt.Errorf("Error reading private key: %v", err)
	}

	var key interface{}
	// jwt.ParseKey detects the PEM block type and returns the correct key interface
	key, err = jwt.ParseEdPrivateKeyFromPEM(privateKeyBytes) // Standard helper
	if err != nil {
		// If ParseEd fails, try general PEM parsing
		key, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
		if err != nil {
			key, err = jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)
			if err != nil {
				return "", fmt.Errorf("Error parsing private key: %v", err)
			}
		}
	}

	var method jwt.SigningMethod

	// Detect key type to choose the algorithm
	switch key.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case ed25519.PrivateKey:
		method = jwt.SigningMethodEdDSA
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}

	// 3. Define the Claims
	claims := jwt.MapClaims{
		"iss": auth.ServiceAccountClientId,
		"sub": auth.ServiceAccountClientId,
		"aud": codeSignServiceAccountJWTAudience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 1).Unix(), // 1 hour expiry
		"jti": uuid.New().String(),
	}

	// 4. Create token with RS256/ES256 method
	token := jwt.NewWithClaims(method, claims)

	// 5. Sign with the RSA Private Key
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error signing token: %v", err)
	}
	return tokenString, nil
}

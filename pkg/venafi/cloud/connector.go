package cloud

import (
	"crypto/x509"
	"fmt"
	"net/http"

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
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignGetObjects, nil)
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

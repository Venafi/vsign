package tpp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	crypto "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/policy"
	"github.com/venafi/vsign/pkg/util"
	"github.com/venafi/vsign/pkg/verror"
)

type Connector struct {
	baseURL     string
	apiKey      string
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	project     string
	client      *http.Client
}

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(url string, project string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	c := Connector{verbose: verbose, trust: trust, project: project}
	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to normalize URL: %v", verror.UserDataError, err)
	}
	return &c, nil
}

// normalizeURL normalizes the base URL used to communicate with TPP
func normalizeURL(url string) (normalizedURL string, err error) {
	var baseUrlRegex = regexp.MustCompile(`^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$`)
	modified := strings.ToLower(url)
	if strings.HasPrefix(modified, "http://") {
		modified = "https://" + modified[7:]
	} else if !strings.HasPrefix(modified, "https://") {
		modified = "https://" + modified
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}

	modified = strings.TrimSuffix(modified, "vedsdk/")

	if loc := baseUrlRegex.FindStringIndex(modified); loc == nil {
		return "", fmt.Errorf("the specified tpp url is invalid. %s\nexpected tpp url format 'https://tpp.company.com/vedsdk/'", url)
	}

	return modified, nil
}

func (c *Connector) SetProject(p string) {
	c.project = p
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeTPP
}

// Ping attempts to connect to the TPP Server WebSDK API and returns an errror if it cannot
func (c *Connector) Ping() (err error) {
	statusCode, status, _, err := c.request("GET", "vedsdk/", nil)
	if err != nil {
		return
	}
	if statusCode != http.StatusOK {
		err = fmt.Errorf("%s", status)
	}
	return
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) GetCredential(auth *endpoint.Authentication) (token string, err error) {
	var data interface{}
	var result interface{}

	if auth.JWT != "" {
		data = oauthGetAccessTokenFromJWTRequest{Client_id: auth.ClientId, Scope: auth.Scope, JWT: auth.JWT}
		result, err = processAuthData(c, urlResourceAuthorizeJWT, data)
		if err != nil {
			return "", err
		}
	} else {
		data = oauthGetRefreshTokenRequest{Client_id: auth.ClientId, Scope: auth.Scope, Username: auth.User, Password: auth.Password}
		result, err = processAuthData(c, urlResourceAuthorizeOAuth, data)
		if err != nil {
			return "", err
		}
	}

	resp := result.(OauthGetRefreshTokenResponse)

	return resp.Access_token, nil

}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = endpoint.DefaultClientID
	}

	if auth.JWT != "" {
		data := oauthGetAccessTokenFromJWTRequest{Client_id: endpoint.DefaultClientID, Scope: endpoint.DefaultScope, JWT: auth.JWT}
		result, err := processAuthData(c, urlResourceAuthorizeJWT, data)
		if err != nil {
			return err
		}
		resp := result.(OauthGetRefreshTokenResponse)
		auth.AccessToken = resp.Access_token
		c.accessToken = resp.Access_token
		return nil
	}

	if auth.User != "" && auth.Password != "" {
		data := authorizeRequest{Username: auth.User, Password: auth.Password}
		result, err := processAuthData(c, urlResourceAuthorize, data)
		if err != nil {
			return err
		}

		resp := result.(authorizeResponse)
		c.apiKey = resp.APIKey
		return nil

	} else if auth.RefreshToken != "" {
		data := oauthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		result, err := processAuthData(c, urlResourceRefreshAccessToken, data)
		if err != nil {
			return err
		}

		resp := result.(OauthRefreshAccessTokenResponse)
		c.accessToken = resp.Access_token
		auth.RefreshToken = resp.Refresh_token
		return nil

	} else if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		return nil
	}
	return fmt.Errorf("failed to authenticate: can't determine valid credentials set")
}

func (c *Connector) RetrieveSystemMajorVersion() (int, error) {
	statusCode, status, body, err := c.request("GET", urlResourceSystemStatusVersion, "")
	if err != nil {
		return 0, err
	}
	//Put in hint for authentication scope 'configuration'
	switch statusCode {
	case 200:
	case 401:
		return 0, fmt.Errorf("http status code '%s' was returned by the server. Hint: OAuth scope 'configuration' is required when using custom fields", status)
	default:
		return 0, fmt.Errorf("unexpected http status code while fetching TPP version. %s", status)
	}

	var response systemStatusVersionResponse
	err = json.Unmarshal(body, &response)

	if err != nil {
		return 0, fmt.Errorf("unexpected error with unmarshaling response. err: %s", err)
	}

	majorVersion := strings.Split(response.Version, ".")[0]

	v, err := strconv.Atoi(majorVersion)
	if err != nil {
		return 0, fmt.Errorf("failed due to Venafi system session's format is invalid. error: %s", err)
	}

	return v, err
}

func (c *Connector) GetEnvironment() (env endpoint.Environment, err error) {
	environmentReq := environmentRequest{policy.RootPath + util.PathSeparator + c.project}
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignGetEnvironment, environmentReq)
	if err != nil {
		return endpoint.Environment{}, err
	}

	env, err = parseEnvironmentResult(statusCode, status, body)
	if err != nil {
		return endpoint.Environment{}, err
	}
	if env.CertificateDN != "" {
		//Fetch certificate based on CertificateEnvironment

		// 23.1 introduced ability to filter by specific KeyId, therefore reducing the token scope needed to use vsign
		version, err := c.RetrieveSystemMajorVersion()
		if err != nil {
			return endpoint.Environment{}, fmt.Errorf("failed to get Venafi system version.  error: %v", err)
		}

		if version == 0 {
			return endpoint.Environment{}, fmt.Errorf("failed to get Venafi system version.  error: %v", err)
		}

		if version > 22 {
			certReq := getObjectsRequest{KeyID: env.KeyID, IncludeChain: true, Experimental: true}
			statusCode, status, body, err = c.request("POST", urlResourceCodeSignGetObjects, certReq)
			if err != nil {
				return endpoint.Environment{}, err
			}
			certs, err := parseGetObjectsResult(statusCode, status, body)
			if err != nil {
				return endpoint.Environment{}, err
			}
			env.CertificateChainData = certs
		} else {
			certReq := certificateRetrieveRequest{CertificateDN: env.CertificateDN, Format: "Base64", IncludeChain: true}
			statusCode, status, body, err = c.request("POST", urlResourceCertificateRetrieve, certReq)
			if err != nil {
				return endpoint.Environment{}, err
			}
			certs, err := parseCertificateRetrievalResult(statusCode, status, body)
			if err != nil {
				return endpoint.Environment{}, err
			}
			env.CertificateChainData = certs
		}
	}

	return env, nil

}

func (c *Connector) GetEnvironmentKeyAlgorithm() (environmentKeyAlg string, err error) {
	environmentReq := environmentRequest{policy.RootPath + util.PathSeparator + c.project}
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignGetEnvironment, environmentReq)
	if err != nil {
		return "", err
	}

	environment, err := parseEnvironmentResult(statusCode, status, body)

	if err != nil {
		return "", fmt.Errorf("parsing environment key algorithm error: [%s] check codesign protect project/environment permissions", err.Error())
	}

	if environment.KeyAlgorithm == "" {
		return "", fmt.Errorf("missing environment keyalgorithm field for %s", environment.CertificateDN)
	}

	/*if err != nil {
		return "", err
	}*/
	return environment.KeyAlgorithm, nil

}

func (c *Connector) GetWKSPublicKeyBytes(email string) (pub []byte, err error) {
	resource := string(urlResourceCodeSignPKSLookup) + email
	statusCode, status, body, err := c.request("GET", urlResource(resource), nil)
	if err != nil {
		return nil, err
	}
	pub, err = parsePKSLookupResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}

	return

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

type Algorithm struct {
	Alg  string `json:"alg,omitempty"`
	Type string `json:"typ,omitempty"`
}

func (c *Connector) SignJWT(keyID string, header string, payload string) (jwt string, err error) {
	signJWTRequest := apiSignJWTRequest{ClientInfo: ClientInfo{endpoint.DefaultClientID, "0.1"}, ProcessInfo: ProcessInfo{endpoint.DefaultClientID}, KeyId: keyID, Header: header, Payload: payload}
	statusCode, status, body, err := c.request("POST", urlResourceCodeSignAPISignJWT, signJWTRequest)

	if err != nil {
		return "", err
	}

	jwt, err = parseSignResult(statusCode, status, body)
	if err != nil {
		return "", err
	}

	return jwt, nil

}

// Get OAuth refresh and access token
func (c *Connector) GetRefreshToken(auth *endpoint.Authentication) (resp OauthGetRefreshTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.Scope == "" {
		auth.Scope = endpoint.DefaultScope
	}
	if auth.ClientId == "" {
		auth.ClientId = endpoint.DefaultClientID
	}

	if auth.User != "" && auth.Password != "" {
		data := oauthGetRefreshTokenRequest{Username: auth.User, Password: auth.Password, Scope: auth.Scope, Client_id: auth.ClientId}
		result, err := processAuthData(c, urlResourceAuthorizeOAuth, data)
		if err != nil {
			return resp, err
		}
		resp = result.(OauthGetRefreshTokenResponse)
		return resp, nil

	} else if auth.ClientPKCS12 {
		data := oauthCertificateTokenRequest{Client_id: auth.ClientId, Scope: auth.Scope}
		result, err := processAuthData(c, urlResourceAuthorizeCertificate, data)
		if err != nil {
			return resp, err
		}

		resp = result.(OauthGetRefreshTokenResponse)
		return resp, nil
	}

	return resp, fmt.Errorf("failed to authenticate: missing credentials")
}

// Refresh OAuth access token
func (c *Connector) RefreshAccessToken(auth *endpoint.Authentication) (resp OauthRefreshAccessTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = endpoint.DefaultClientID
	}

	if auth.RefreshToken != "" {
		data := oauthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		result, err := processAuthData(c, urlResourceRefreshAccessToken, data)
		if err != nil {
			return resp, err
		}
		resp = result.(OauthRefreshAccessTokenResponse)
		return resp, nil
	} else {
		return resp, fmt.Errorf("failed to authenticate: missing refresh token")
	}
}

// VerifyAccessToken - call to check whether token is valid and, if so, return its properties
func (c *Connector) VerifyAccessToken(auth *endpoint.Authentication) (resp OauthVerifyTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		statusCode, statusText, body, err := c.request("GET", urlResource(urlResourceAuthorizeVerify), nil)
		if err != nil {
			return resp, err
		}

		if statusCode == http.StatusOK {
			var result = &OauthVerifyTokenResponse{}
			err = json.Unmarshal(body, result)
			if err != nil {
				return resp, fmt.Errorf("failed to parse verify token response: %s, body: %s", err, body)
			}
			return *result, nil
		}
		return resp, fmt.Errorf("failed to verify token. Message: %s", statusText)
	}

	return resp, fmt.Errorf("failed to authenticate: missing access token")
}

// RevokeAccessToken - call to revoke token so that it can never be used again
func (c *Connector) RevokeAccessToken(auth *endpoint.Authentication) (err error) {

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		statusCode, statusText, _, err := c.request("GET", urlResource(urlResourceRevokeAccessToken), nil)
		if err != nil {
			return err
		}

		if statusCode == http.StatusOK {
			return nil
		}
		return fmt.Errorf("failed to revoke token. Message: %s", statusText)
	}

	return fmt.Errorf("failed to authenticate: missing access token")
}

func processAuthData(c *Connector, url urlResource, data interface{}) (resp interface{}, err error) {

	statusCode, status, body, err := c.request("POST", url, data)
	if err != nil {
		return resp, err
	}

	var getRefresh OauthGetRefreshTokenResponse
	var refreshAccess OauthRefreshAccessTokenResponse
	var authorize authorizeResponse

	if statusCode == http.StatusOK {
		switch data.(type) {
		case oauthGetRefreshTokenRequest, oauthGetAccessTokenFromJWTRequest:
			err = json.Unmarshal(body, &getRefresh)
			if err != nil {
				return resp, err
			}
			log.Trace().Msgf("processAuthData oauthGetRefreshTokenRequest/oauthGetAccessTokenFromJWTRequest response:\n%s\n", string(body))
			resp = getRefresh
		case oauthRefreshAccessTokenRequest:
			err = json.Unmarshal(body, &refreshAccess)
			if err != nil {
				return resp, err
			}
			log.Trace().Msgf("processAuthData oauthRefreshAccessTokenRequest response:\n%s\n", string(body))
			resp = refreshAccess
		case authorizeRequest:
			err = json.Unmarshal(body, &authorize)
			if err != nil {
				return resp, err
			}
			resp = authorize
		case oauthCertificateTokenRequest:
			err = json.Unmarshal(body, &getRefresh)
			if err != nil {
				return resp, err
			}
			log.Trace().Msgf("processAuthData oauthCertificateTokenRequest response:\n%s\n", string(body))
			resp = getRefresh
		default:
			return resp, fmt.Errorf("can not determine data type")
		}
	} else {
		return resp, fmt.Errorf("unexpected status code on TPP Authorize. Status: %s, Details: %s", status, NewAuthenticationError(body))
	}

	return resp, nil
}

// Fetches PEM Certificate from PKS endpoint
// Pre-requisite is 23.1+
func GetPKSCertificate(url string) (*x509.Certificate, error) {
	var statusCode int
	var statusText string

	r, _ := http.NewRequest("GET", url, nil)
	r.Close = true

	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	netTransport.TLSClientConfig = tlsConfig
	client := &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	if res != nil {
		statusCode = res.StatusCode
		statusText = res.Status
	}

	if statusCode == http.StatusOK {
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		log.Trace().Msgf("GetPKSCertificate response:\n%s\n", string(body))
		block, _ := pem.Decode(body)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate retrieval via PKS failed response: %s, body: %s", err, body)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("certificate retrieval via PKS failed. Message: %s", statusText)

}

// Fetches JKWS for a specific code signing certificate
// Pre-requisite is 23.1+
func (c *Connector) GetJwksX5u(cert *x509.Certificate) (string, error) {
	version, err := c.RetrieveSystemMajorVersion()
	if err != nil {
		return "", err
	}

	if version > 22 {
		fingerprint := sha256.Sum256(cert.Raw)
		statusCode, status, body, err := c.request("GET", urlResourceCodeSignJWKSLookup+urlResource(fmt.Sprintf("%x", fingerprint)), nil)
		if err != nil {
			return "", err
		}

		x5u, err := parseJWKSLookupResult(statusCode, status, body)
		if err != nil {
			return "", err
		}
		// Need to strip JSON double quotes
		return x5u[1 : len(x5u)-1], nil

	} else {
		return "", verror.UnSupportedAPI
	}

}

func (c *Connector) SetKeyLabel(label string) {
	panic("operation not supported for tpp")
}

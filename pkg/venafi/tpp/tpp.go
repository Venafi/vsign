package tpp

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
)

type urlResource string

type authorizeResponse struct {
	APIKey     string `json:",omitempty"`
	ValidUntil string `json:",omitempty"` //todo: add usage
}

type authorizeRequest struct {
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
}

type oauthRefreshAccessTokenRequest struct {
	Refresh_token string `json:"refresh_token,omitempty"`
	Client_id     string `json:"client_id"`
}

type oauthGetRefreshTokenRequest struct {
	Client_id string `json:"client_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}

type oauthGetAccessTokenFromJWTRequest struct {
	Client_id string `json:"client_id"`
	JWT       string `json:"jwt"`
	Scope     string `json:"scope"`
}

type OauthGetRefreshTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Scope         string `json:"scope,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}

type OauthRefreshAccessTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}

type oauthCertificateTokenRequest struct {
	Client_id string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
}

type OauthVerifyTokenResponse struct {
	AccessIssuedOn string `json:"access_issued_on_ISO8601,omitempty"`
	ClientID       string `json:"application,omitempty"`
	Expires        string `json:"expires_ISO8601,omitempty"`
	GrantIssuedOn  string `json:"grant_issued_on_ISO8601,omitempty"`
	Identity       string `json:"identity,omitempty"`
	Scope          string `json:"scope,omitempty"`
	ValidFor       int    `json:"valid_for,omitempty"`
}

type environmentRequest struct {
	EnvironmentDN string `json:"Dn"`
}

type KeyAlgorithm struct {
	Value string `json:",omitempty"`
}

type CertificateEnvironment struct {
	Guid          string `json:",omitempty"`
	CertificateDN string `json:",omitempty"`
	KeyAlgorithm  KeyAlgorithm
}

type KeyPairEnvironment struct {
	Guid         string `json:",omitempty"`
	KeyAlgorithm KeyAlgorithm
}

type environmentRequestResponse struct {
	KeyPairEnvironment     KeyPairEnvironment
	CertificateEnvironment CertificateEnvironment
	Result                 int    `json:",omitempty"`
	Success                bool   `json:",omitempty"`
	Error                  string `json:",omitempty"`
}

type ClientInfo struct {
	ClientLibraryName    string `json:",omitempty"`
	ClientLibraryVersion string `json:",omitempty"`
}

type ProcessInfo struct {
	Executable string `json:",omitempty"`
}

type ParameterInfo struct {
	MGF           int    `json:",omitempty"`
	ParameterType string `json:",omitempty"`
	HashAlg       int    `json:",omitempty"`
	SaltLen       int    `json:",omitempty"`
}

type apiSignRequest struct {
	ClientInfo      ClientInfo
	ProcessInfo     ProcessInfo
	KeyId           string        `json:",omitempty"`
	ClientMechanism int           `json:",omitempty"`
	Mechanism       int           `json:",omitempty"`
	ParameterInfo   ParameterInfo `json:"Parameter,omitempty"`
	Data            string        `json:",omitempty"`
}

type apiSignResponse struct {
	ResultData string `json:",omitempty"`
	Success    bool   `json:",omitempty"`
	Error      string `json:",omitempty"`
}

type apiSignJWTRequest struct {
	ClientInfo  ClientInfo
	ProcessInfo ProcessInfo
	KeyId       string `json:",omitempty"`
	Header      string `json:",omitempty"`
	Payload     string `json:",omitempty"`
}

type certificateRetrieveRequest struct {
	CertificateDN     string `json:",omitempty"`
	Format            string `json:",omitempty"`
	Password          string `json:",omitempty"`
	IncludePrivateKey bool   `json:",omitempty"`
	IncludeChain      bool   `json:",omitempty"`
	FriendlyName      string `json:",omitempty"`
	RootFirstOrder    bool   `json:",omitempty"`
}

type certificateRetrieveResponse struct {
	CertificateData string `json:",omitempty"`
	Format          string `json:",omitempty"`
	Filename        string `json:",omitempty"`
	Status          string `json:",omitempty"`
	Stage           int    `json:",omitempty"`
}

const (
	urlResourceAuthorize              urlResource = "vedsdk/authorize"
	urlResourceRefreshAccessToken     urlResource = "vedauth/authorize/token" // #nosec
	urlResourceAuthorizeOAuth         urlResource = "vedauth/authorize/oauth"
	urlResourceAuthorizeCertificate   urlResource = "vedauth/authorize/certificate"
	urlResourceAuthorizeJWT           urlResource = "vedauth/authorize/jwt"
	urlResourceAuthorizeVerify        urlResource = "vedauth/authorize/verify"
	urlResourceRevokeAccessToken      urlResource = "vedauth/revoke/token" // #nosec
	urlResourceCodeSignGetEnvironment urlResource = "vedsdk/codesign/getenvironment"
	urlResourceCodeSignAPISign        urlResource = "vedhsm/api/sign"
	urlResourceCodeSignAPISignJWT     urlResource = "vedhsm/api/signjwt"
	urlResourceCodeSignPKSLookup      urlResource = "pks/lookup?op=get&search="
	urlResourceCertificateRetrieve    urlResource = "vedsdk/certificates/retrieve"
	urlResourceCodeSignGetChain       urlResource = "vedhsm/api/getchain"
)

func (c *Connector) request(method string, resource urlResource, data interface{}) (statusCode int, statusText string, body []byte, err error) {
	url := c.baseURL + string(resource)
	var payload io.Reader
	var b []byte
	if method == "POST" || method == "PUT" {
		b, _ = json.Marshal(data)
		payload = bytes.NewReader(b)
	}

	r, _ := http.NewRequest(method, url, payload)
	r.Close = true
	if c.accessToken != "" {
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	} else if c.apiKey != "" {
		r.Header.Add("x-venafi-api-key", c.apiKey)
	}
	r.Header.Add("content-type", "application/json")
	r.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(r)
	if res != nil {
		statusCode = res.StatusCode
		statusText = res.Status
	}
	if err != nil {
		return
	}

	defer res.Body.Close()
	body, err = io.ReadAll(res.Body)
	// Do not enable trace in production
	trace := false // IMPORTANT: sensitive information can be diclosured
	// I hope you know what are you doing
	if trace {
		log.Println("#################")
		log.Printf("Headers are:\n%s", r.Header)
		if method == "POST" || method == "PUT" {
			log.Printf("JSON sent for %s\n%s\n", url, string(b))
		} else {
			log.Printf("%s request sent to %s\n", method, url)
		}
		log.Printf("Response:\n%s\n", string(body))
	} else if c.verbose {
		log.Printf("Got %s status for %s %s\n", statusText, method, url)
	}
	return
}

func (c *Connector) getHTTPClient() *http.Client {
	if c.client != nil {
		return c.client
	}
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
	/* #nosec */
	if c.trust != nil {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
	}
	netTransport.TLSClientConfig = tlsConfig
	c.client = &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}
	return c.client
}

func parseEnvironmentResult(httpStatusCode int, httpStatus string, body []byte) (endpoint.Environment, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseEnvironmentData(body)
		if reqData.Error != "" {
			return endpoint.Environment{}, fmt.Errorf(reqData.Error)
		}
		if err != nil {
			return endpoint.Environment{}, err
		}
		if reqData.KeyPairEnvironment.Guid != "" {
			return endpoint.Environment{KeyID: reqData.KeyPairEnvironment.Guid, KeyAlgorithm: reqData.KeyPairEnvironment.KeyAlgorithm.Value, CertificateDN: ""}, nil
		}
		return endpoint.Environment{KeyID: reqData.CertificateEnvironment.Guid, KeyAlgorithm: reqData.CertificateEnvironment.KeyAlgorithm.Value, CertificateDN: reqData.CertificateEnvironment.CertificateDN}, nil
	default:
		return endpoint.Environment{}, fmt.Errorf("unexpected status code on TPP Environment Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}
}

func parseCertificateRetrievalResult(httpStatusCode int, httpStatus string, body []byte) ([][]byte, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseCertificateRetrievalData(body)
		if err != nil {
			return nil, err
		}
		decData, err := base64.StdEncoding.DecodeString(reqData.CertificateData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 certificate")
		}

		certs, err := c.ParsePEM(decData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificates")
		}

		certChain := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			certChain = append(certChain, cert.Raw)
		}
		/*block, _ := pem.Decode(decData)
		if block == nil {
			return nil, fmt.Errorf("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
		}*/

		return certChain, nil
	default:
		return nil, fmt.Errorf("unexpected status code on TPP Environment Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}

}

func parseEnvironmentData(b []byte) (data environmentRequestResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseCertificateRetrievalData(b []byte) (data certificateRetrieveResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseSignResult(httpStatusCode int, httpStatus string, body []byte) (string, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseSignData(body)
		if reqData.Error != "" {
			return "", fmt.Errorf("unexpected error from API/Sign: %s", reqData.Error)
		}
		if err != nil {
			return "", err
		}
		return reqData.ResultData, nil
	default:
		return "", fmt.Errorf("unexpected status code on TPP Sign Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}
}

func parseSignData(b []byte) (data apiSignResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parsePKSLookupResult(httpStatusCode int, httpStatus string, body []byte) ([]byte, error) {
	switch httpStatusCode {
	case http.StatusOK:

		/*if reqData.Error != "" {
			return "", fmt.Errorf("Unexpected error from PKS/Lookup: %s", reqData.Error)
		}
		if err != nil {
			return "", err
		}*/
		return body, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found")
	default:
		return nil, fmt.Errorf("unexpected status code on TPP PKS/Lookup.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}
}

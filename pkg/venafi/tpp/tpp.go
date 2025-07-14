package tpp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
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

type getObjectsRequest struct {
	KeyID        string `json:"KeyId,omitempty"`
	IncludeChain bool   `json:"IncludeChains,omitempty"`
	Experimental bool   `json:"Experimental,omitempty"`
}

type Certificate struct {
	Value string `json:",omitempty"`
}

type getObjectsResponse struct {
	Certificates []Certificate `json:",omitempty"`
	PublicKeys   []PublicKey   `json:",omitempty"`
}

type JWKS struct {
	X5U string `json:"x5u,omitempty"`
}
type systemStatusVersionResponse struct {
	Version string `json:",omitempty"`
}

type jwksLookupResponse struct {
	Keys []JWKS `json:"keys,omitempty"`
}

type PublicKey struct {
	KeyId    string `json:"KeyId,omitempty"`
	Label    string `json:"Label,omitempty"`
	KeyType  int    `json:"KeyType,omitempty"`  // 0=RSA, 3=EC
	ECPoint  string `json:"ECPoint,omitempty"`  // EC only
	Params   string `json:"Params,omitempty"`   // EC only
	Curve    string `json:"Curve,omitempty"`    // EC only
	Bits     int    `json:"Bits,omitempty"`     // RSA only
	Exponent string `json:"Exponent,omitempty"` // RSA only
	Modulus  string `json:"Modulus,omitempty"`  // RSA only

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
	urlResourceCodeSignJWKSLookup     urlResource = "pks/lookup/jwks?x509Thumbprints="
	urlResourceCertificateRetrieve    urlResource = "vedsdk/certificates/retrieve"
	urlResourceCodeSignGetChain       urlResource = "vedhsm/api/getchain"
	urlResourceCodeSignGetObjects     urlResource = "vedhsm/api/getobjects"
	urlResourceSystemStatusVersion    urlResource = "vedsdk/systemstatus/version"
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

	//
	// Limit trace level logging in production as sensitive information may be disclosed
	//

	log.Trace().Msgf("Headers are:\n%s", r.Header)
	if method == "POST" || method == "PUT" {
		log.Trace().Msgf("JSON sent for %s\n%s\n", url, string(b))
	} else {
		log.Trace().Msgf("%s request sent to %s\n", method, url)
	}
	log.Trace().Msgf("Response:\n%s\n", string(body))

	log.Trace().Msgf("Got %s status for %s %s\n", statusText, method, url)

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
		log.Trace().Msgf(string(urlResourceCodeSignGetEnvironment)+" response:\n%s\n", string(body))
		reqData, err := parseEnvironmentData(body)
		if reqData.Error != "" {
			return endpoint.Environment{}, fmt.Errorf("parseenvironment error: %s", reqData.Error)
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

func parseGetObjectsResult(httpStatusCode int, httpStatus string, body []byte) ([][]byte, crypto.PublicKey, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		log.Trace().Msgf(string(urlResourceCodeSignGetObjects)+" response:\n%s\n", string(body))
		reqData, err := parseGetObjectsData(body)
		if err != nil {
			return nil, nil, err
		}
		if len(reqData.Certificates) > 0 {
			certChain := make([][]byte, 0, len(reqData.Certificates))
			for _, cert := range reqData.Certificates {
				decData, err := base64.StdEncoding.DecodeString(cert.Value)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to decode base64 certificate")
				}
				c, err := x509.ParseCertificate(decData)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing certificate")
				}
				certChain = append(certChain, c.Raw)

			}

			return certChain, nil, nil
		} else {
			switch reqData.PublicKeys[0].KeyType {
			case c.CryptokiKeyRSA:
				decodedModulus, err := base64.StdEncoding.DecodeString(reqData.PublicKeys[0].Modulus)
				if err != nil {
					return nil, nil, err
				}
				decodedExponent, err := base64.StdEncoding.DecodeString(reqData.PublicKeys[0].Exponent)
				if err != nil {
					return nil, nil, err
				}

				modulus := new(big.Int).SetBytes(decodedModulus)
				exponent := new(big.Int).SetBytes(decodedExponent)

				publicKey := &rsa.PublicKey{
					N: modulus,
					E: int(exponent.Int64()), // Assuming exponent fits in an int64
				}

				return nil, publicKey, nil
			case c.CryptokiKeyEC:

				// 1. Decode Base64 parameters
				decodedBytes, err := base64.StdEncoding.DecodeString(reqData.PublicKeys[0].ECPoint)
				if err != nil {
					fmt.Printf("Error decoding X: %v\n", err)
					return nil, nil, err
				}

				switch reqData.PublicKeys[0].Curve {
				case "P256":
					pubKey := &ecdsa.PublicKey{
						Curve: elliptic.P256(),
						X:     big.NewInt(0).SetBytes(decodedBytes[1:33]),
						Y:     big.NewInt(0).SetBytes(decodedBytes[33:]),
					}
					return nil, pubKey, nil
				case "P384":
					pubKey := &ecdsa.PublicKey{
						Curve: elliptic.P384(),
						X:     big.NewInt(0).SetBytes(decodedBytes[1:49]),
						Y:     big.NewInt(0).SetBytes(decodedBytes[49:]),
					}
					return nil, pubKey, nil
				case "P521":
					pubKey := &ecdsa.PublicKey{
						Curve: elliptic.P521(),
						X:     big.NewInt(0).SetBytes(decodedBytes[1:67]),
						Y:     big.NewInt(0).SetBytes(decodedBytes[67:]),
					}
					return nil, pubKey, nil
				default:
					return nil, nil, fmt.Errorf("unknown curve public key")

				}

			default:
				return nil, nil, fmt.Errorf("cannot decode public key with keytype: %d", reqData.PublicKeys[0].KeyType)
			}
		}
	default:
		return nil, nil, fmt.Errorf("unexpected status code on TPP Environment Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)

	}
}

func parseCertificateRetrievalResult(httpStatusCode int, httpStatus string, body []byte) ([][]byte, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		log.Trace().Msgf(string(urlResourceCertificateRetrieve)+" response:\n%s\n", string(body))
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

func parseGetObjectsData(b []byte) (data getObjectsResponse, err error) {
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
		log.Trace().Msgf(string(urlResourceCodeSignAPISign)+" response:\n%s\n", string(body))
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

func parseJWKSData(b []byte) (data jwksLookupResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseJWKSLookupResult(httpStatusCode int, httpStatus string, body []byte) (string, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		log.Trace().Msgf(string(urlResourceCodeSignJWKSLookup)+" response:\n%s\n", string(body))
		reqData, err := parseJWKSData(body)
		if err != nil {
			return "", err
		}
		return reqData.Keys[0].X5U, nil
	default:
		return "", fmt.Errorf("unexpected status code on TPP JWKS Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}
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
		log.Trace().Msgf(string(urlResourceCodeSignPKSLookup)+" response:\n%s\n", string(body))
		return body, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found")
	default:
		return nil, fmt.Errorf("unexpected status code on TPP PKS/Lookup.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}
}

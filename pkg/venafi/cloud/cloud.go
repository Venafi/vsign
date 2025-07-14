package cloud

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
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
	"github.com/venafi/vsign/pkg/util"
)

type urlResource string

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

type getObjectsRequest struct {
	KeyID        string `json:"KeyId,omitempty"`
	IncludeChain bool   `json:"IncludeChains,omitempty"`
	Experimental bool   `json:"Experimental,omitempty"`
}

type Certificate struct {
	Value string `json:",omitempty"`
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

type getObjectsResponse struct {
	Certificates []Certificate `json:",omitempty"`
	PublicKeys   []PublicKey   `json:",omitempty"`
}

const (
	apiURL                                    = "api.venafi.cloud"
	urlResourceCodeSignAPISign    urlResource = "vedhsm/api/sign"
	urlResourceCodeSignGetObjects urlResource = "vedhsm/api/getobjects"
)

func (c *Connector) request(method string, resource urlResource, data interface{}) (statusCode int, statusText string, body []byte, err error) {
	url := c.baseURL + string(resource)
	var payload io.Reader
	var b []byte

	if data == nil {
		payload = nil
	} else {
		if method == "POST" || method == "PUT" {
			b, _ = json.Marshal(data)
			payload = bytes.NewReader(b)
		}
	}

	r, _ := http.NewRequest(method, url, payload)
	r.Close = true
	if c.accessToken != "" {
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	} else if c.apiKey != "" {
		r.Header.Add(util.HeaderTpplApikey, c.apiKey)
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

func parseGetObjectsResult(httpStatusCode int, httpStatus string, body []byte, label string) (string, crypto.PublicKey, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		log.Trace().Msgf(string(urlResourceCodeSignGetObjects)+" response:\n%s\n", string(body))
		reqData, err := parseGetObjectsData(body)
		if err != nil {
			return "", nil, err
		}
		for _, pKey := range reqData.PublicKeys {
			if pKey.Label == label {

				switch pKey.KeyType {
				case c.CryptokiKeyRSA:
					decodedModulus, err := base64.StdEncoding.DecodeString(pKey.Modulus)
					if err != nil {
						return "", nil, err
					}
					decodedExponent, err := base64.StdEncoding.DecodeString(pKey.Exponent)
					if err != nil {
						return "", nil, err
					}

					modulus := new(big.Int).SetBytes(decodedModulus)
					exponent := new(big.Int).SetBytes(decodedExponent)

					publicKey := &rsa.PublicKey{
						N: modulus,
						E: int(exponent.Int64()), // Assuming exponent fits in an int64
					}

					return pKey.KeyId, publicKey, nil
				case c.CryptokiKeyEC:

					// 1. Decode Base64 parameters
					decodedBytes, err := base64.StdEncoding.DecodeString(pKey.ECPoint)
					if err != nil {
						fmt.Printf("Error decoding X: %v\n", err)
						return "", nil, err
					}

					switch pKey.Curve {
					case "P256":
						pubKey := &ecdsa.PublicKey{
							Curve: elliptic.P256(),
							X:     big.NewInt(0).SetBytes(decodedBytes[1:33]),
							Y:     big.NewInt(0).SetBytes(decodedBytes[33:]),
						}
						return pKey.KeyId, pubKey, nil
					case "P384":
						pubKey := &ecdsa.PublicKey{
							Curve: elliptic.P384(),
							X:     big.NewInt(0).SetBytes(decodedBytes[1:49]),
							Y:     big.NewInt(0).SetBytes(decodedBytes[49:]),
						}
						return pKey.KeyId, pubKey, nil
					case "P521":
						pubKey := &ecdsa.PublicKey{
							Curve: elliptic.P521(),
							X:     big.NewInt(0).SetBytes(decodedBytes[1:67]),
							Y:     big.NewInt(0).SetBytes(decodedBytes[67:]),
						}
						return pKey.KeyId, pubKey, nil
					default:
						return "", nil, fmt.Errorf("unknown curve public key")

					}

				default:
					return "", nil, fmt.Errorf("cannot decode public key with keytype: %d", pKey.KeyType)
				}

			}
		}

		return "", nil, fmt.Errorf("cannot retrieve keyid with label %s", label)

		/*certChain := make([][]byte, 0, len(reqData.Certificates))
		for _, cert := range reqData.Certificates {
			decData, err := base64.StdEncoding.DecodeString(cert.Value)
			if err != nil {
				return "", fmt.Errorf("failed to decode base64 certificate")
			}
			c, err := x509.ParseCertificate(decData)
			if err != nil {
				return "", fmt.Errorf("error parsing certificate")
			}
			certChain = append(certChain, c.Raw)

		}

		return certChain, nil*/
	default:
		return "", nil, fmt.Errorf("unexpected status code on TPP Environment Request.\n Status:\n %s. \n Body:\n %s", httpStatus, body)
	}

}

func parseGetObjectsData(b []byte) (data getObjectsResponse, err error) {
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

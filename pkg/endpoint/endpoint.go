package endpoint

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
)

type ConnectorType int

const (
	ConnectorTypeUndefined ConnectorType = iota
	// ConnectorTypeTPP represents the TPP connector type
	ConnectorTypeTPP
	ConnectorTypeCloud

	DefaultClientID = "vsign-sdk"
	DefaultScope    = "codesignclient;codesign;certificate:manage,discover"
)

func init() {
	log.SetPrefix("vSign: ")
}

func (t ConnectorType) String() string {
	switch t {
	case ConnectorTypeUndefined:
		return "Undefined Endpoint"
	case ConnectorTypeTPP:
		return "TPP"
	case ConnectorTypeCloud:
		return "Cloud"
	default:
		return fmt.Sprintf("unexpected connector type: %d", t)
	}
}

// Connector provides a common interface for external communications with TPP or Venafi Cloud
type Connector interface {
	// GetType returns a connector type (cloud/TPP/fake). Can be useful because some features are not supported by a Cloud connection.
	GetType() ConnectorType
	// SetProject sets a project (by name) for TPP requests with this connector.
	SetProject(p string)
	// SetKeyLabel sets a signing key (by label) for Cloud requests with this connector.
	SetKeyLabel(label string)
	// Get codesign protect environment keyid
	GetEnvironment() (Environment, error)
	// Get codesign protect environment key algorithm
	GetEnvironmentKeyAlgorithm() (string, error)
	// Sign
	//Sign(keyID string, mechanism int, digest string, data string, b64 bool, raw bool) ([]byte, error)
	Sign(so *SignOption) ([]byte, error)
	// Sign JWT
	SignJWT(KeyID string, headerPath string, payloadPath string) (string, error)
	// Get GPG public keys
	GetWKSPublicKeyBytes(email string) ([]byte, error)
	// Get JWKS
	GetJwksX5u(cert *x509.Certificate) (string, error)
	Ping() (err error)
	// Authenticate is usually called by NewClient and it is not required that you manually call it.
	Authenticate(auth *Authentication) (err error)
	GetCredential(auth *Authentication) (token string, err error)
	SetHTTPClient(client *http.Client)
}

type Filter struct {
	Limit       *int
	WithExpired bool
}

// Authentication provides a struct for authentication data. Either specify User and Password for Trust Platform or specify an APIKey for Cloud.
type Authentication struct {
	User         string
	Password     string
	APIKey       string
	JWT          string
	RefreshToken string
	Scope        string
	ClientId     string
	AccessToken  string
	ClientPKCS12 bool
}

type Environment struct {
	KeyID                string
	KeyAlgorithm         string
	CertificateDN        string
	CertificateChainData [][]byte
}

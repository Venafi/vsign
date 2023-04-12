package vsign

import (
	"crypto/x509"
	"fmt"
	"log"

	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/venafi/tpp"
	"github.com/venafi/vsign/pkg/verror"
)

// NewClient returns a connector for the Trust Protection Platform (TPP) configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to TPP that can be reused without restriction.
func (cfg *Config) NewClient() (connector endpoint.Connector, err error) {
	var connectionTrustBundle *x509.CertPool

	if cfg.ConnectionTrust != "" {
		log.Println("You specified a trust bundle.")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", verror.UserDataError)
		}
	}

	switch cfg.ConnectorType {
	case endpoint.ConnectorTypeTPP:
		connector, err = tpp.NewConnector(cfg.BaseUrl, cfg.Project, cfg.LogVerbose, connectionTrustBundle)
	default:
		err = fmt.Errorf("%w: ConnectorType is not defined", verror.UserDataError)
	}
	if err != nil {
		return
	}

	connector.SetProject(cfg.Project)
	connector.SetHTTPClient(cfg.Client)

	if cfg.Credentials.User != "" && cfg.Credentials.Password != "" {
		return
	}

	if cfg.Credentials.AccessToken != "" || cfg.Credentials.JWT != "" {
		err = connector.Authenticate(cfg.Credentials)
	} else {
		var errstr string
		if cfg.Credentials.AccessToken == "" {
			errstr = "no access token specified"
		}
		if cfg.Credentials.JWT == "" {
			errstr += ", no JWT specified"
		}
		return nil, fmt.Errorf("failed to authenticate: %s", errstr)

	}
	return
}

// NewClient returns a connector for either Trust Protection Platform (TPP) configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to TPP that can be reused without restriction.
func NewClient(cfg *Config) (endpoint.Connector, error) {
	return cfg.NewClient()
}

package vsign

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/venafi/cloud"
	"github.com/venafi/vsign/pkg/venafi/tpp"
	"github.com/venafi/vsign/pkg/verror"
)

// NewClient returns a connector for the Trust Protection Platform (TPP) or Code Sign Manager Cloud configuration.
// Config should have Credentials compatible with the selected ConnectorType.
// Returned connector is a concurrency-safe interface to TPP that can be reused without restriction.
func (cfg *Config) NewClient() (connector endpoint.Connector, err error) {
	var connectionTrustBundle *x509.CertPool

	if cfg.ConnectionTrust != "" {
		//log.Println("You specified a trust bundle.")
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		log.Info().Msg("You specified a trust bundle.")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", verror.UserDataError)
		}
	}

	switch cfg.ConnectorType {
	case endpoint.ConnectorTypeTPP:
		connector, err = tpp.NewConnector(cfg.BaseUrl, cfg.Project, cfg.LogVerbose, connectionTrustBundle)
		connector.SetProject(cfg.Project)
	case endpoint.ConnectorTypeCloud:
		connector, err = cloud.NewConnector(cfg.BaseUrl, cfg.KeyLabel, cfg.LogVerbose, connectionTrustBundle)
	default:
		err = fmt.Errorf("%w: ConnectorType is not defined", verror.UserDataError)
	}
	if err != nil {
		return
	}

	connector.SetHTTPClient(cfg.Client)

	if cfg.Credentials.User != "" && cfg.Credentials.Password != "" {
		return
	}

	if cfg.Credentials.AccessToken != "" || cfg.Credentials.JWT != "" || cfg.Credentials.APIKey != "" {
		err = connector.Authenticate(cfg.Credentials)
	} else {
		var errstr string
		if cfg.Credentials.AccessToken == "" {
			errstr = "no access token specified"
		}
		if cfg.Credentials.JWT == "" {
			errstr += ", no JWT specified"
		}
		if cfg.Credentials.APIKey == "" {
			errstr += ", no API Key specificed"
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

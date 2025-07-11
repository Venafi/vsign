package vsign

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/venafi/vsign/pkg/endpoint"
	"gopkg.in/ini.v1"
)

// Config is a basic structure for high level initiating connector to Trust Platform (TPP)/Venafi Cloud
type Config struct {
	// ConnectorType specify what do you want to use. May be "TPP" or "Cloud".
	ConnectorType endpoint.ConnectorType
	// BaseUrl should be specified for Venafi Platform.
	BaseUrl string
	// Project is name of a CodeSign Protect project in Venafi Platform. For TPP, if necessary, escape backslash symbols.   For example,  "test\\zone" or `test\zone`.
	Project string
	// KeyLabel is the unique key label for a Signing Key in Code Sign Manager Cloud
	KeyLabel string
	// Credentials should contain either User and Password for TPP connections.
	Credentials *endpoint.Authentication
	// ConnectionTrust  may contain a trusted CA or certificate of server if you use self-signed certificate.
	ConnectionTrust string // *x509.CertPool
	LogVerbose      bool
	// http.Client to use during construction
	Client *http.Client
}

func BuildConfigWithAuth(c context.Context, url string, cred *endpoint.Authentication, trust_bundle string) (cfg Config, err error) {

	// Load configuration from environment variables
	var connectorType endpoint.ConnectorType
	var auth = &endpoint.Authentication{}

	// Defaults
	connectorType = endpoint.ConnectorTypeTPP
	cfg.LogVerbose = false
	cfg.ConnectorType = connectorType
	auth.AccessToken = ""
	auth.Scope = endpoint.DefaultScope
	auth.ClientId = endpoint.DefaultClientID

	if cred.User != "" && cred.Password != "" {
		auth.User = cred.User
		auth.Password = cred.Password
	}

	if cred.JWT != "" {
		auth.JWT = cred.JWT
	}

	cfg.Credentials = auth
	cfg.BaseUrl = url

	if trust_bundle != "" {
		data, err := os.ReadFile(trust_bundle)
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	return cfg, err

}

func BuildConfig(c context.Context, config string) (cfg Config, err error) {

	if config != "" {
		// Loading configuration from file
		cfg, err = loadConfigFromFile(config, "")
		if err != nil {
			return cfg, err
		}
	} else {
		// Load configuration from environment variables
		var connectorType endpoint.ConnectorType
		var baseURL string
		var auth = &endpoint.Authentication{}

		token := getPropertyFromEnvironment(vSignToken)   // TPP environment variable
		jwt := getPropertyFromEnvironment(vSignJWT)       // TPP environment variable
		apiKey := getPropertyFromEnvironment(vSignAPIKey) // Cloud environment variable

		url := getPropertyFromEnvironment(vSignURL)
		if url != "" {
			baseURL = url
		} else {
			return cfg, fmt.Errorf("venafi codeSign protect TPP or Cloud base url is required")
		}

		connectorType = endpoint.ConnectorTypeTPP

		if token != "" {
			auth.AccessToken = token
		}

		if jwt != "" {
			auth.JWT = jwt
		}

		if apiKey != "" {
			auth.APIKey = apiKey
			connectorType = endpoint.ConnectorTypeCloud
		}

		cfg.ConnectorType = connectorType
		cfg.Credentials = auth
		cfg.BaseUrl = baseURL
		cfg.LogVerbose = false

		project := getPropertyFromEnvironment(vSignProject)
		if project != "" {
			cfg.Project = project
		} else {
			if cfg.ConnectorType == endpoint.ConnectorTypeTPP {
				return cfg, fmt.Errorf("a valid venafi codeSign protect project is required")
			}
		}

		keyLabel := getPropertyFromEnvironment(vSignKeyLabel)
		if keyLabel != "" {
			cfg.KeyLabel = keyLabel
		} else {
			if cfg.ConnectorType == endpoint.ConnectorTypeCloud {
				return cfg, fmt.Errorf("a valid venafi cloud key lable is required")
			}
		}

		// Use trust bundle if supplied
		trust_bundle := getPropertyFromEnvironment(vSignTrustBundle)
		if trust_bundle != "" {
			data, err := os.ReadFile(trust_bundle)
			if err != nil {
				return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
			}
			cfg.ConnectionTrust = string(data)
		}
	}
	return cfg, nil
}

func (cfg *Config) GetKeyLabel() string {
	var result string = cfg.Project
	result = strings.Replace(result, "\\\\", "-", -1)
	result = strings.Replace(result, "\\", "-", -1)
	result = strings.Replace(result, " ", "-", -1)

	return result

}

// LoadConfigFromFile is deprecated. In the future will be rewrited.
func loadConfigFromFile(path, section string) (cfg Config, err error) {

	if section == "" {
		// nolint:staticcheck
		section = ini.DefaultSection
	}
	// TODO need configurable debugging option
	//fmt.Printf("Loading configuration from %s section %s", path, section)

	fname, err := expand(path)

	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	iniFile, err := ini.Load(fname)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	err = validateFile(iniFile)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	ok := func() bool {
		for _, s := range iniFile.Sections() {
			if s.Name() == section {
				return true
			}
		}
		return false
	}()
	if !ok {
		return cfg, fmt.Errorf("section %s has not been found in %s", section, path)
	}

	var m dict = iniFile.Section(section).KeysHash()

	var connectorType endpoint.ConnectorType
	var baseUrl string
	var auth = &endpoint.Authentication{}
	if m.has("access_token") || m.has("jwt") {
		connectorType = endpoint.ConnectorTypeTPP
		if m["tpp_url"] != "" {
			baseUrl = m["tpp_url"]
		} else if m["url"] != "" {
			baseUrl = m["url"]
		}
		auth.AccessToken = m["access_token"]
		if m.has("tpp_project") {
			cfg.Project = m["tpp_project"]
		}
	} else if m.has("cloud_apikey") {
		connectorType = endpoint.ConnectorTypeCloud
		auth.APIKey = m["cloud_apikey"]
		if m["cloud_url"] != "" {
			baseUrl = m["cloud_url"]
		}
		if m["url"] != "" {
			baseUrl = m["url"]
		}
		if m.has("cloud_keylabel") {
			cfg.KeyLabel = m["cloud_keylabel"]
		}
	} else {
		return cfg, fmt.Errorf("failed to load config: connector type cannot be defined")
	}

	if m.has("jwt") {
		auth.JWT = m["jwt"]
	}

	if m.has("trust_bundle") {
		fname, err := expand(m["trust_bundle"])
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		data, err := os.ReadFile(fname)
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	cfg.ConnectorType = connectorType
	cfg.Credentials = auth
	cfg.BaseUrl = baseUrl
	cfg.LogVerbose = false

	return
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

type dict map[string]string

func (d dict) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

type set map[string]bool

func (d set) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

func validateSection(s *ini.Section) error {
	var TPPValidKeys set = map[string]bool{
		"url":          true,
		"access_token": true,
		"tpp_url":      true,
		"jwt":          true,
		"tpp_project":  true,
		"trust_bundle": true,
	}

	var CloudValidKeys set = map[string]bool{
		"url":            true,
		"cloud_apikey":   true,
		"cloud_keylabel": true,
	}

	//fmt.Fprintf(os.Stdout, "Validating configuration section %s", s.Name())
	var m dict = s.KeysHash()

	if (m.has("access_token") || m.has("jwt")) && m.has("cloud_apikey") {
		return fmt.Errorf("configuration issue in section %s: only one between TPP access token, cloud api key or jwt can be set", s.Name())
	}

	if m.has("jwt") || m.has("access_token") {
		// looks like TPP config section
		for k := range m {
			if !TPPValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in TPP section %s", k, s.Name())
			}
		}
		if m.has("jwt") && m.has("access_token") {
			return fmt.Errorf("configuration issue in section %s: could not have both TPP JWT and access token", s.Name())
		}
	} else if m.has("cloud_apikey") {
		// looks like Cloud config section
		for k := range m {
			if !CloudValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in Cloud section %s", k, s.Name())
			}
		}
	} else if m.has("test_mode") {
		// it's ok

	} else if m.has("url") {
		return fmt.Errorf("could not determine connection endpoint with only url information in section %s", s.Name())
	} else {
		return fmt.Errorf("section %s looks empty", s.Name())
	}
	return nil
}

func validateFile(f *ini.File) error {

	for _, section := range f.Sections() {
		if len(section.Keys()) == 0 {
			if len(f.Sections()) > 1 {
				// empty section is not valid. skipping it if there are more sections in the file
				//fmt.Fprintf(os.Stdout, "Warning: empty section %s", section.Name())
				continue
			}
		}
		err := validateSection(section)
		if err != nil {
			return err
		}
	}
	return nil
}

//
// Copyright 2022 Venafi.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package getcred

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

const UtilityShortName string = "vSign"

var (
	tlsConfig tls.Config
	logger    = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
)

func setTLSConfig() error {
	//tlsConfig.InsecureSkipVerify = true
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func GetCredCmd(ctx context.Context, credOpts options.GetCredOptions, args []string) error {

	err := setTLSConfig()
	if err != nil {
		return fmt.Errorf("error setting TLS config")
	}

	// TODO better logic for validating arguments
	if (credOpts.Username != "" && credOpts.Password != "") || credOpts.JWT != "" {
		cfg, err := vsign.BuildConfigWithAuth(ctx, credOpts.Url, &endpoint.Authentication{User: credOpts.Username, Password: credOpts.Password, JWT: credOpts.JWT}, credOpts.TrustBundle)
		if err != nil {
			logger.Printf("error building config: %s", err)
			return fmt.Errorf("error building config")
		}
		connector, err := vsign.NewClient(&cfg)
		if err != nil {
			logger.Printf("Unable to connect to %s: %s", cfg.ConnectorType, err)
		} else {
			logger.Printf("Successfully connected to %s", cfg.ConnectorType)
		}

		auth := &endpoint.Authentication{
			User:     credOpts.Username,
			Password: credOpts.Password,
			JWT:      credOpts.JWT,
			Scope:    endpoint.DefaultScope,
			ClientId: endpoint.DefaultClientID}

		resp, err := connector.GetCredential(auth)
		if err != nil {
			logger.Printf("error fetching token: %s", err)
			return fmt.Errorf("error fetching token")
		}
		println("access_token: " + resp)
	} else {
		return fmt.Errorf("missing tpp credentials")
	}

	return nil
}

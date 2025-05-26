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

package jwt

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/pkg/vsign"
)

const UtilityShortName string = "vSign"

var (
	tlsConfig tls.Config
	logger    = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
)

func setTLSConfig() error {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func SignJWTCmd(ctx context.Context, jwtOpts options.JWTOptions, args []string) error {
	err := setTLSConfig()
	if err != nil {
		return fmt.Errorf("erro setting TLS config")
	}
	cfg, err := vsign.BuildConfig(ctx, jwtOpts.Config)
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

	env, err := connector.GetEnvironment()
	if err != nil {
		return err
	}

	payload, err := os.ReadFile(jwtOpts.PayloadPath)
	if err != nil {
		return fmt.Errorf("error with payload path")
	}

	header, err := os.ReadFile(jwtOpts.HeaderPath)
	if err != nil {
		return fmt.Errorf("error with payload path")
	}

	token, err := connector.SignJWT(env.KeyID, base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload))

	if err != nil {
		return fmt.Errorf("signjwt error: %s", err.Error())
	}

	println(token)

	return nil
}

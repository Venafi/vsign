//
// Copyright 2021 Venafi.
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

package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/provider/magic"
	"github.com/venafi/vsign/pkg/vsign"
)

const UtilityShortName string = "vSign"

var (
	tlsConfig tls.Config
	//logger    = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
)

func setTLSConfig() error {
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func VerifyCmd(ctx context.Context, verifyOpts options.VerifyOptions, args []string) error {
	var connector endpoint.Connector

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true})

	f, err := os.Open(verifyOpts.SignaturePath)
	if err != nil {
		return err
	}
	defer f.Close()

	err = setTLSConfig()
	if err != nil {
		return fmt.Errorf("erro setting TLS config")
	}

	if verifyOpts.Config != "" {

		cfg, err := vsign.BuildConfig(ctx, verifyOpts.Config)
		if err != nil {
			//logger.Printf("error building config: %s", err)
			return fmt.Errorf("error building config: %s", err)
		}

		connector, err = vsign.NewClient(&cfg)
		if err != nil {
			return fmt.Errorf("unable to connect to %s: %s", cfg.ConnectorType, err)
		} else {

			log.Info().Msgf("Successfully connected to %s", cfg.ConnectorType)
		}
	}

	opts := signers.VerifyOpts{}
	fileType, compression := magic.DetectCompressed(f)
	opts.FileName = verifyOpts.SignaturePath
	opts.Compression = compression
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	mod := signers.ByMagic(fileType)
	if mod == nil {
		mod = signers.ByFileName(verifyOpts.SignaturePath)
	}
	if mod == nil {
		return fmt.Errorf("unknown filetype")
	}

	if mod.VerifyStream != nil {
		r, err2 := magic.Decompress(f, opts.Compression)
		if err2 != nil {
			return err
		}
		err = mod.VerifyStream(r, opts)
	} else {
		if opts.Compression != magic.CompressedNone {
			return fmt.Errorf("cannot verify compressed file")
		}
		err = mod.Verify(f, verifyOpts, signers.VerifyOpts{Platform: connector, NoDigests: true})
		if err != nil {
			return fmt.Errorf("verification error: %v", err.Error())
		}
	}
	if err != nil {
		return fmt.Errorf("%w; unknown verification error", err)
	}

	log.Info().Msg("Verification successful")
	return nil
}

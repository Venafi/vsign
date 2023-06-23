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

package sign

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/spf13/pflag"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/provider/audit"
	"github.com/venafi/vsign/pkg/provider/certloader"
	cp "github.com/venafi/vsign/pkg/provider/cosign"
)

const UtilityShortName string = "vSign"

type KeyOpts struct {
	KeyRef string
}

var (
	tlsConfig tls.Config
	logger    = log.New(os.Stderr, UtilityShortName+": ", log.LstdFlags)
)

func setTLSConfig() error {
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func SignCmd(ctx context.Context, fs *pflag.FlagSet, signOpts options.SignOptions, args []string) error {
	err := setTLSConfig()
	if err != nil {
		return fmt.Errorf("erro setting TLS config")
	}

	info, err := os.Stat(signOpts.PayloadPath)
	if err != nil {
		return fmt.Errorf("error obtaining payload size")
	}

	if !isValidPayloadSizeForMechanism(info.Size(), signOpts.Mechanism) {
		return fmt.Errorf("payload size is invalid for server-side hashing mechanism.  use client-side hashing mechanisms for large payloads")
	}

	cfg, err := vsign.BuildConfig(ctx, signOpts.Config)
	if err != nil {
		logger.Printf("error building config: %s", err)
		return fmt.Errorf("error building config")
	}

	connector, err := vsign.NewClient(&cfg)
	if err != nil {
		logger.Printf("Unable to connect to %s: %s", cfg.ConnectorType, err)
		return err
	} else {
		logger.Printf("Successfully connected to %s", cfg.ConnectorType)
	}

	env, err := connector.GetEnvironment()
	if err != nil {
		return err
	}

	if signOpts.ImageRef != "" {
		data, err := cp.GenerateImageManifest(ctx, signOpts.ImageRef, nil)
		if err != nil {
			return fmt.Errorf("error with cosign image manifest download")
		}

		sig, err := connector.Sign(&endpoint.SignOption{
			KeyID:     env.KeyID,
			Mechanism: signOpts.Mechanism,
			DigestAlg: signOpts.Digest,
			Payload:   []byte(c.EncodeBase64(data)),
			B64Flag:   true,
			RawFlag:   false,
		})

		if err != nil {
			return fmt.Errorf(err.Error())
		}

		if cp.WriteSignatures(ctx, signOpts.ImageRef, data, sig, c.EncodeBase64(sig)) != nil {
			return fmt.Errorf(err.Error())
		}
		fmt.Fprintln(os.Stderr, "Pushing signature to: ", signOpts.ImageRef)
		return nil
	}

	//if strings.Contains(signOpts.PayloadPath, "jar") {
	// detect signature type
	mod, err := signers.ByFile(signOpts.PayloadPath, signOpts.SigType)
	if err != nil {
		return shared.Fail(err)
	}
	if mod.Sign == nil {
		return shared.Fail(fmt.Errorf("can't sign files of type: %s", mod.Name))
	}
	// parse signer-specific flags
	flags, err := mod.FlagsFromCmdline(fs)
	if err != nil {
		return shared.Fail(err)
	}
	infile, err := shared.OpenForPatching(signOpts.PayloadPath, signOpts.OutputSignature)
	if err != nil {
		return shared.Fail(err)
	} else if infile == os.Stdin {
		if !mod.AllowStdin {
			return shared.Fail(errors.New("this signature type does not support reading from stdin"))
		}
	} else {
		defer infile.Close()
	}
	// transform input if needed
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}

	opts := &signers.SignOpts{
		TPP:       connector,
		KeyID:     env.KeyID,
		Mechanism: signOpts.Mechanism,
		Digest:    signOpts.Digest,
		Path:      signOpts.PayloadPath,
		Hash:      hash,
		Flags:     flags,
		Audit:     audit.New(cfg.Project, endpoint.DefaultClientID, hash),
		KeyLabel:  cfg.GetKeyLabel(),
	}
	// transform the input, sign the stream, and apply the result
	transform, err := mod.GetTransform(infile, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	stream, err := transform.GetReader()
	if err != nil {
		return shared.Fail(err)
	}

	certs, err := c.ParseCertificates(env.CertificateChainData)
	if err != nil {
		return shared.Fail(err)
	}
	var cert certloader.Certificate = certloader.Certificate{Leaf: certs[0], Certificates: certs}
	blob, err := mod.Sign(stream, &cert, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	mimeType := opts.Audit.GetMimeType()
	if err := transform.Apply(signOpts.OutputSignature, mimeType, bytes.NewReader(blob)); err != nil {
		return shared.Fail(err)
	}
	// if needed, do a final fixup step
	if mod.Fixup != nil {
		f, err := os.OpenFile(signOpts.OutputSignature, os.O_RDWR, 0)
		if err != nil {
			return shared.Fail(err)
		}
		defer f.Close()
		if err := mod.Fixup(f); err != nil {
			return shared.Fail(err)
		}
	}

	fmt.Fprintln(os.Stderr, "Pushing signature to:", signOpts.OutputSignature)
	return nil
}

func isValidPayloadSizeForMechanism(size int64, mechanism int) bool {

	if (size > 10000) && mechanism != c.EcDsa && mechanism != c.RsaPkcs && mechanism != c.RsaPkcsPss {
		return false
	}

	return true
}

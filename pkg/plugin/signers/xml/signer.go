//
// Copyright (c) SAS Institute Inc.
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
//

package xml

// Sign Java archives

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/common-nighthawk/go-figure"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/provider/magic"
	"github.com/venafi/vsign/pkg/provider/xmldsig"
)

var XMLSigner = &signers.Signer{
	Name:      "xml",
	Magic:     magic.FileTypeXML,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
	TestPath:  testpath,
}

func init() {
	signers.Register(XMLSigner)
}

func testpath(string) bool {
	fmt.Println("testing path")
	return false
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, certs []*x509.Certificate, opts signers.SignOpts) ([]byte, error) {

	experimental := figure.NewFigure("experimental: XML signing", "", true)
	experimental.Print()

	var err error
	var data []byte

	if opts.Path != "" {
		data, err = os.ReadFile(opts.Path)
		if err != nil {
			return nil, fmt.Errorf("error with payload path")
		}
	}

	signer, err := xmldsig.NewSigner(data, opts)

	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	signedXML, err := signer.Sign()

	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	return signedXML, nil
}

func verify(f *os.File, opts options.VerifyOptions, tppOpts signers.VerifyOpts) error {

	experimental := figure.NewFigure("experimental: XML signing", "", true)
	experimental.Print()

	if tppOpts.TPP == nil {
		return fmt.Errorf("this plugin currently only supports online certificate verification via TPP.  please use provider TPP configuration via --config parameter")
	}

	var err error
	var data []byte

	if opts.SignaturePath != "" {
		data, err = os.ReadFile(opts.SignaturePath)
		if err != nil {
			return err
		}
	}

	validator, err := xmldsig.NewValidator(string(data), tppOpts)
	if err != nil {
		return fmt.Errorf("error with validator")
	}

	env, err := tppOpts.TPP.GetEnvironment()
	if err != nil {
		return err
	}

	validator.Certificates, err = c.ParseCertificates(env.CertificateChainData)

	if err != nil {
		return fmt.Errorf("error with certificate chain")
	}

	_, err = validator.ValidateReferences()
	if err != nil {
		return fmt.Errorf("error during XML signature verification: %v", err.Error())
	}

	return nil
}

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

package pdf

// Sign PDFs

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/provider/certloader"
	"github.com/venafi/vsign/pkg/provider/magic"
	"github.com/venafi/vsign/pkg/provider/pdfsig"
	verifier "github.com/venafi/vsign/pkg/provider/pdfsig/verify"
)

var PDFSigner = &signers.Signer{
	Name:      "pdf",
	Magic:     magic.FileTypePDF,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
	TestPath:  testpath,
}

func init() {
	PDFSigner.Flags().String("name", "Acme Signer", "Name of the signatory")
	PDFSigner.Flags().String("location", "Palo Alto", "Location of the signatory")
	PDFSigner.Flags().String("reason", "Contract", "Reason for signing")
	PDFSigner.Flags().String("contact", "acme@example.com", "Contact information for the signatory")
	PDFSigner.Flags().String("tsa", "http://timestamp.digicert.com", "URL for Time-Stamp Authority (default: http://timestamp.digicert.com)")
	PDFSigner.Flags().Bool("visual", false, "add visual signature to pdf")
	signers.Register(PDFSigner)
}

func testpath(string) bool {
	fmt.Println("testing path")
	return false
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, certs []*x509.Certificate, opts signers.SignOpts) ([]byte, error) {
	var err error

	if certs == nil {
		return nil, fmt.Errorf("certificate environment must be used")
	}

	var cert certloader.Certificate = certloader.Certificate{Leaf: certs[0], Certificates: certs}

	certificate_chains := make([][]*x509.Certificate, 0)
	certificate_chains = append(certificate_chains, cert.Chain())

	_, hasher, _ := c.GetHasher(opts.Digest)

	var ctype pdfsig.CertType
	var app pdfsig.Appearance

	if opts.Flags.GetBool("visual") {
		experimental := figure.NewFigure("experimental: pdf signing with visual signatures", "", true)
		experimental.Print()
		ctype = pdfsig.ApprovalSignature
		app = pdfsig.Appearance{
			Visible:     true,
			LowerLeftX:  350,
			LowerLeftY:  75,
			UpperRightX: 600,
			UpperRightY: 100,
		}
	} else {
		ctype = pdfsig.CertificationSignature
		app = pdfsig.Appearance{
			Visible:     false,
			LowerLeftX:  350,
			LowerLeftY:  75,
			UpperRightX: 600,
			UpperRightY: 100,
		}
	}

	signedPayload, err := pdfsig.SignFile(r, pdfsig.SignData{
		Signature: pdfsig.SignDataSignature{
			Info: pdfsig.SignDataSignatureInfo{
				Name:        opts.Flags.GetString("name"),
				Location:    opts.Flags.GetString("location"),
				Reason:      opts.Flags.GetString("reason"),
				ContactInfo: opts.Flags.GetString("contact"),
				Date:        time.Now().Local(),
			},
			CertType:   ctype,
			DocMDPPerm: pdfsig.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		PlatformOpts:      opts,
		Appearance:        app,
		DigestAlgorithm:   hasher,
		Certificate:       cert.Leaf,
		CertificateChains: certificate_chains,
		TSA: pdfsig.TSA{
			URL: opts.Flags.GetString("tsa"),
		},
	})

	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	return signedPayload, nil
}

func verify(f *os.File, opts options.VerifyOptions, tppOpts signers.VerifyOpts) error {
	_, err := verifier.File(f)
	if err != nil {
		return err
	}

	return nil
}

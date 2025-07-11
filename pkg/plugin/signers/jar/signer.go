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

package jar

// Sign Java archives

import (
	"archive/zip"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/common-nighthawk/go-figure"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/plugin/signers/zipbased"
	"github.com/venafi/vsign/pkg/provider/certloader"
	"github.com/venafi/vsign/pkg/provider/jar"
	"github.com/venafi/vsign/pkg/provider/magic"
)

var JarSigner = &signers.Signer{
	Name:      "jar",
	Magic:     magic.FileTypeJAR,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	JarSigner.Flags().Bool("sections-only", false, "(JAR) Don't compute hash of entire manifest")
	JarSigner.Flags().Bool("inline-signature", false, "(JAR) Include .SF inside the signature block")
	JarSigner.Flags().Bool("apk-v2-present", false, "(JAR) Add X-Android-APK-Signed header to signature")
	signers.Register(JarSigner)
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, certs []*x509.Certificate, opts signers.SignOpts) ([]byte, error) {
	experimental := figure.NewFigure("experimental: Jar signing", "", true)
	experimental.Print()

	if certs == nil {
		return nil, fmt.Errorf("certificate environment must be used")
	}

	var cert certloader.Certificate = certloader.Certificate{Leaf: certs[0], Certificates: certs}

	argSectionsOnly := opts.Flags.GetBool("sections-only")
	argInlineSignature := opts.Flags.GetBool("inline-signature")
	argApkV2 := opts.Flags.GetBool("apk-v2-present")

	digest, err := jar.DigestJarStream(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	patch, ts, err := digest.Sign(opts.Context(), &cert, opts.KeyLabel, argSectionsOnly, argInlineSignature, argApkV2, opts.Platform)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts options.VerifyOptions, platformOpts signers.VerifyOpts) error {
	experimental := figure.NewFigure("experimental: Jar signing", "", true)
	experimental.Print()

	if platformOpts.Platform == nil {
		return fmt.Errorf("this plugin currently only supports online certificate verification via TPP.  please use provider TPP configuration via --config parameter")
	}

	inz, err := openZip(f)
	if err != nil {
		return err
	}
	_, err = jar.Verify(inz, platformOpts.NoDigests)
	if err != nil {
		return err
	}

	return nil
}

func openZip(f *os.File) (*zip.Reader, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	return zip.NewReader(f, size)
}

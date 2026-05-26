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
	"bytes"
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

// verify checks the cryptographic integrity of a signed JAR file.
//
// Two security properties are enforced (CWE-347):
//  1. Digest validation – every file entry listed in MANIFEST.MF is hashed
//     and compared against its recorded digest (controlled by NoDigests in
//     platformOpts; the caller must NOT set NoDigests: true for production use).
//  2. Trust anchor validation – each PKCS#7 signature block is verified to
//     chain up to a root CA that the Venafi platform considers authoritative.
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

	// Verify manifest digests and parse the embedded PKCS#7 signature blocks.
	// platformOpts.NoDigests must be false (the default) for full integrity
	// checking; a true value skips per-entry hash validation (CWE-347).
	sigs, err := jar.Verify(inz, platformOpts.NoDigests)
	if err != nil {
		return err
	}

	if len(sigs) == 0 {
		return fmt.Errorf("JAR contains no valid signatures")
	}

	// --- Trust anchor validation (CWE-347) ---
	//
	// Retrieve the certificate chain associated with the signing environment
	// from the Venafi platform.  The chain is used to build an authoritative
	// trust pool so that we can confirm each JAR signature was made by a key
	// whose certificate chains to a known, trusted root CA.
	env, err := platformOpts.Platform.GetEnvironment()
	if err != nil {
		return fmt.Errorf("failed to retrieve platform environment for trust anchor validation: %w", err)
	}

	if len(env.CertificateChainData) == 0 {
		return fmt.Errorf("platform returned an empty certificate chain; cannot perform trust anchor validation")
	}

	// Partition the chain into root CAs (trust anchors) and intermediates.
	// A certificate is a root CA when its Subject and Issuer raw bytes are
	// identical (self-signed).
	trustedPool := x509.NewCertPool()
	var intermediates []*x509.Certificate
	rootFound := false

	for _, derBytes := range env.CertificateChainData {
		cert, parseErr := x509.ParseCertificate(derBytes)
		if parseErr != nil {
			return fmt.Errorf("failed to parse certificate from platform chain: %w", parseErr)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			// Self-signed → root CA → trust anchor
			trustedPool.AddCert(cert)
			rootFound = true
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	if !rootFound {
		return fmt.Errorf("no self-signed root CA found in platform certificate chain; cannot establish trust anchor")
	}

	// Validate the full X.509 chain for every signature found in the JAR.
	// This rejects JARs signed by keys that do not chain to a trusted root,
	// closing the CWE-347 trust-anchor gap.
	for i, sig := range sigs {
		if err := sig.TimestampedSignature.VerifyChain(trustedPool, intermediates, x509.ExtKeyUsageCodeSigning); err != nil {
			return fmt.Errorf("JAR signature %d failed trust chain validation: %w", i+1, err)
		}
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

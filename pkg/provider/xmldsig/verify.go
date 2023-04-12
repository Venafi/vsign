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

package xmldsig

import (
	"crypto"
	"crypto/x509"
	"os"

	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/venafi/vsign/cmd/vsign/cli/options"

	"github.com/beevik/etree"
)

type Signature struct {
	PublicKey       crypto.PublicKey
	Certificates    []*x509.Certificate
	Hash            crypto.Hash
	EncryptedDigest []byte
	Reference       *etree.Element
}

func (s Signature) Leaf() *x509.Certificate {
	for _, cert := range s.Certificates {
		if x509tools.SameKey(cert.PublicKey, s.PublicKey) {
			return cert
		}
	}
	return nil
}

// Extract and verify an enveloped signature at the given root
func Verify(f *os.File, opts options.VerifyOptions) error {

	return nil
	//fmt.Printf("certificate: %v", validator.SigningCert())

}

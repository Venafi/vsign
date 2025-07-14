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

package signers

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/pflag"
	"github.com/venafi/vsign/pkg/endpoint"
	"golang.org/x/crypto/openpgp"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/venafi/vsign/pkg/provider/audit"
	"github.com/venafi/vsign/pkg/provider/magic"
	"github.com/venafi/vsign/pkg/provider/pkcs7"
	"github.com/venafi/vsign/pkg/provider/pkcs9"
)

type SignOpts struct {
	Platform  endpoint.Connector
	Mechanism int
	Digest    string
	KeyID     string
	KeyLabel  string
	Path      string
	Hash      crypto.Hash
	Time      time.Time
	Flags     *FlagValues
	Audit     *audit.Info
	ctx       context.Context
}

// Convenience method to return a binary patch
func (o SignOpts) SetBinPatch(p *binpatch.PatchSet) ([]byte, error) {
	o.Audit.SetMimeType(binpatch.MimeType)
	return p.Dump(), nil
}

// Convenience method to return a PKCS#7 blob
func (o SignOpts) SetPkcs7(ts *pkcs9.TimestampedSignature) ([]byte, error) {
	o.Audit.SetCounterSignature(ts.CounterSignature)
	o.Audit.SetMimeType(pkcs7.MimeType)
	return ts.Raw, nil
}

// WithContext attaches a context to the signature operation, and can be used to cancel long-running operations.
func (o SignOpts) WithContext(ctx context.Context) SignOpts {
	o.ctx = ctx
	return o
}

// Context returns the context attached to the signature operation.
//
// The returned context is always non-nil; it defaults to the background context.
func (o SignOpts) Context() context.Context {
	if o.ctx != nil {
		return o.ctx
	}
	return context.Background()
}

type VerifyOpts struct {
	Platform    endpoint.Connector
	FileName    string
	TrustedX509 []*x509.Certificate
	TrustedPgp  openpgp.EntityList
	TrustedPool *x509.CertPool
	PublicKey   crypto.PublicKey
	NoDigests   bool
	NoChain     bool
	Content     string
	Compression magic.CompressionType
}

type FlagValues struct {
	Defs   *pflag.FlagSet
	Values map[string]string
}

// FlagsFromCmdline creates a FlagValues from the (merged) command-line options of a command
func (s *Signer) FlagsFromCmdline(fs *pflag.FlagSet) (*FlagValues, error) {
	for flag, users := range flagMap {
		if !fs.Changed(flag) {
			continue
		}
		allowed := false
		for _, name := range users {
			if name == s.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("flag \"%s\" is not allowed for signature type \"%s\"", flag, s.Name)
		}
	}
	if s.flags == nil {
		return nil, nil
	}
	values := &FlagValues{
		Defs:   s.flags,
		Values: make(map[string]string),
	}
	s.flags.VisitAll(func(flag *pflag.Flag) {
		if fs.Changed(flag.Name) {
			values.Values[flag.Name] = fs.Lookup(flag.Name).Value.String()
		}
	})
	return values, nil
}

// FlagsFromQuery creates a FlagValues from URL query parameters
func (s *Signer) FlagsFromQuery(q url.Values) (*FlagValues, error) {
	if s.flags == nil {
		return nil, nil
	}
	values := &FlagValues{
		Defs:   s.flags,
		Values: make(map[string]string),
	}
	s.flags.VisitAll(func(flag *pflag.Flag) {
		if value := q.Get(flag.Name); value != "" {
			values.Values[flag.Name] = value
		}
	})
	return values, nil
}

// ToQuery appends query parameters to a URL for each option in the flag set
func (values *FlagValues) ToQuery(q url.Values) error {
	if values == nil {
		return nil
	}
	for key, value := range values.Values {
		q.Set(key, value)
	}
	return nil
}

// GetString returns the flag's value as a string
func (values *FlagValues) GetString(name string) string {
	if values == nil {
		panic("flag " + name + " not defined for signer module")
	}
	flag := values.Defs.Lookup(name)
	if flag == nil {
		panic("flag " + name + " not defined for signer module")
	}
	if v, ok := values.Values[name]; ok {
		return v
	}
	return flag.DefValue
}

// GetBool returns the flag's value as a bool
func (values *FlagValues) GetBool(name string) bool {
	str := values.GetString(name)
	b, _ := strconv.ParseBool(str)
	return b
}

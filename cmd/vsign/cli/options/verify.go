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

package options

import (
	"github.com/spf13/cobra"
)

// SignOptions is the top level wrapper for the sign command.
type VerifyOptions struct {
	Config        string
	SignaturePath string // TODO: this should be the root output file arg.
	PayloadPath   string
	PublicKeyPath string
	Digest        string
	Force         bool
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {

	cmd.Flags().StringVar(&o.Config, "config", "",
		"path to the Venafi configuration file")

	cmd.Flags().StringVar(&o.SignaturePath, "signature", "",
		"write the signature to FILE")

	cmd.Flags().StringVar(&o.PublicKeyPath, "key", "",
		"public key for verification")

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")

	cmd.Flags().StringVar(&o.Digest, "digest", "",
		"sha digest algorithm")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")
}

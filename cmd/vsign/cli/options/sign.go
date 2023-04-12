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
type SignOptions struct {
	Config          string
	ImageRef        string
	OutputSignature string
	PayloadPath     string
	Digest          string
	Mechanism       int
	SigType         string
	Jar             JarOptions
}

var _ Interface = (*SignOptions)(nil)

// AddFlags implements Interface
func (o *SignOptions) AddFlags(cmd *cobra.Command) {

	o.Jar.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Config, "config", "",
		"path to the Venafi configuration file")
	_ = cmd.Flags().SetAnnotation("config", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.ImageRef, "image", "",
		"path to a container image")
	_ = cmd.Flags().SetAnnotation("image", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.Flags().SetAnnotation("output-signature", cobra.BashCompFilenameExt, []string{"output"})

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")
	_ = cmd.Flags().SetAnnotation("payload", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.Digest, "digest", "",
		"sha digest algorithm")
	_ = cmd.Flags().SetAnnotation("digest", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().IntVar(&o.Mechanism, "mechanism", 4164,
		"mechanism")
	_ = cmd.Flags().SetAnnotation("mechanism", cobra.BashCompFilenameExt, []string{"mech"})

	cmd.Flags().StringVar(&o.SigType, "sig-type", "", "Specify signature type (default: auto-detect)")
	_ = cmd.Flags().SetAnnotation("sig-type", cobra.BashCompFilenameExt, []string{"sig"})

}

//
// Copyright 2022 Venafi.
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
type GetCredOptions struct {
	Url         string
	Username    string
	Password    string
	JWT         string
	TrustBundle string
}

var _ Interface = (*GetCredOptions)(nil)

// AddFlags implements Interface
func (o *GetCredOptions) AddFlags(cmd *cobra.Command) {

	cmd.Flags().StringVar(&o.Url, "url", "",
		"path to the Venafi TPP server")

	cmd.Flags().StringVar(&o.Username, "username", "",
		"CSP username")

	cmd.Flags().StringVar(&o.Password, "password", "",
		"CSP user password")

	cmd.Flags().StringVar(&o.JWT, "jwt", "",
		"JWT")

	cmd.Flags().StringVar(&o.TrustBundle, "trust-bundle", "",
		"Trust bundle")

	cmd.MarkFlagsRequiredTogether("username", "password")
	cmd.MarkFlagRequired("url")

}

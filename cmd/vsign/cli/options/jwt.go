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
type JWTOptions struct {
	Config      string
	HeaderPath  string
	PayloadPath string
}

var _ Interface = (*JWTOptions)(nil)

// AddFlags implements Interface
func (o *JWTOptions) AddFlags(cmd *cobra.Command) {

	cmd.Flags().StringVar(&o.Config, "config", "",
		"path to the Venafi configuration file")

	cmd.Flags().StringVar(&o.HeaderPath, "header", "",
		"JWT Header")

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to the JWT payload file")

	cmd.MarkFlagsRequiredTogether("header", "payload")

}

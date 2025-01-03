//
// Copyright Venafi 2022.
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

package cli

import (
	"github.com/spf13/cobra"
	"github.com/venafi/vsign/cmd/vsign/cli/jwt"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
)

func JWT() *cobra.Command {
	o := &options.JWTOptions{}

	cmd := &cobra.Command{
		Use:     "jwt",
		Short:   "Sign the supplied JWT payload.",
		Long:    "Sign the supplied JWT payload.",
		Example: `  vsign jwt --config <config path> --header <path> --payload <path> --algorithm <algorithm>`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := jwt.SignJWTCmd(cmd.Context(), *o, args); err != nil {

				//return errors.Wrapf(err, "signing failed")
				return err
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}

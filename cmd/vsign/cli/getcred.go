//
// Copyright Venafi.
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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/venafi/vsign/cmd/vsign/cli/getcred"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
)

func GetCred() *cobra.Command {
	o := &options.GetCredOptions{}

	cmd := &cobra.Command{
		Use:     "getcred",
		Short:   "obtain a new credential (token) for authentication or exchange a JWT for a new credential (token)",
		Long:    "Obtain a new credential (token) for authentication or exchange a JWT for a new credential (token)",
		Example: `  vsign getcred -u https://tpp.example.com --username <csp user> --password <csp user password> [--jwt <jwt>] `,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := getcred.GetCredCmd(cmd.Context(), *o, args); err != nil {

				return errors.Wrapf(err, "getcred failed")
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}

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
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/cmd/vsign/cli/sign"
)

func Sign() *cobra.Command {
	o := &options.SignOptions{}

	cmd := &cobra.Command{
		Use:     "sign",
		Short:   "Sign the supplied payload.",
		Long:    "Sign the supplied payload.",
		Example: `  vsign sign --config <config path> --output-signature <path> --payload <path> --image <image> --mechanism <mechanism_id> --digest <digest_alg>  --trust-bundle <path to CA chain PEM>`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := sign.SignCmd(cmd.Context(), cmd.Flags(), *o, args); err != nil {

				return errors.Wrapf(err, "signing failed")
			}
			return nil
		},
	}
	o.AddFlags(cmd)

	return cmd
}

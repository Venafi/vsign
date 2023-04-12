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

package cli

import (
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/cmd/vsign/cli/shared"
	"github.com/venafi/vsign/pkg/plugin/signers"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	var (
		out, stdout *os.File
	)

	cmd := &cobra.Command{
		Use:               "vsign",
		DisableAutoGenTag: true,
		SilenceUsage:      true, // Don't show usage on errors
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if ro.OutputFile != "" {
				var err error
				out, err = os.Create(ro.OutputFile)
				if err != nil {
					return errors.Wrapf(err, "Error creating output file %s", ro.OutputFile)
				}
				stdout = os.Stdout
				os.Stdout = out // TODO: don't do this.
				cmd.SetOut(out)
			}

			if ro.Verbose {
				logs.Debug.SetOutput(os.Stderr)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if out != nil {
				_ = out.Close()
			}
			os.Stdout = stdout
		},
	}
	ro.AddFlags(cmd)

	// Add sub-commands.

	cmd.AddCommand(Sign())
	cmd.AddCommand(Verify())
	cmd.AddCommand(JWT())
	cmd.AddCommand(version.WithFont("starwars"))
	cmd.AddCommand(GetCred())
	cmd.AddCommand(Completion())

	shared.AddLateHook(func() {
		signers.MergeFlags(cmd)
	})

	return cmd
}

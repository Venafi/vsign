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

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/venafi/vsign/cmd/vsign/cli/shared"
	"github.com/venafi/vsign/pkg/plugin/signers"
)

/*var (
	ro = &options.RootOptions{}
)*/

var rootOpts struct {
	verbosity string
	logopts   []string
}

func New() *cobra.Command {
	var (
		out, stdout *os.File
	)

	cmd := &cobra.Command{
		Use:               "vsign",
		DisableAutoGenTag: true,
		SilenceUsage:      true, // Don't show usage on errors
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

			/*if !cmd.Flags().Changed("verbosity") {
				zerolog.SetGlobalLevel(zerolog.Disabled)
			}*/

			switch rootOpts.verbosity {
			case "trace":
				zerolog.SetGlobalLevel(zerolog.TraceLevel)
			case "debug":
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			case "info":
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			case "warn":
				zerolog.SetGlobalLevel(zerolog.WarnLevel)
			case "error":
				zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			case "fatal":
				zerolog.SetGlobalLevel(zerolog.FatalLevel)
			case "panic":
				zerolog.SetGlobalLevel(zerolog.PanicLevel)
			default:
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
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

	cmd.PersistentFlags().StringVarP(&rootOpts.verbosity, "verbosity", "v", zerolog.InfoLevel.String(), "Log level (trace, debug, info, warn, error, fatal, panic)")
	//cmd.PersistentFlags().StringArrayVar(&rootOpts.logopts, "logopt", []string{}, "Log options")
	cmd.RegisterFlagCompletionFunc("verbosity", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}, cobra.ShellCompDirectiveNoFileComp
	})

	//ro.AddFlags(cmd)

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

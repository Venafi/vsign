package cli

import (
	"os"

	"github.com/spf13/cobra"
)

func Completion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:
Bash:
  $ source <(cosign completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ cosign completion bash > /etc/bash_completion.d/cosign
  # macOS:
  $ cosign completion bash > /usr/local/etc/bash_completion.d/cosign
Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, execute once:
  $ cosign completion zsh > "${fpath[1]}/_cosign"
  # You will need to start a new shell for this setup to take effect.
fish:
  $ cosign completion fish | source
  # To load completions for each session, execute once:
  $ cosign completion fish > ~/.config/fish/completions/cosign.fish
PowerShell:
  PS> cosign completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> cosign completion powershell > cosign.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				_ = cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				_ = cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				_ = cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}

	//o.AddFlags(cmd)
	return cmd
}

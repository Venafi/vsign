package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/venafi/vsign/cmd/vsign/cli"
)

func main() {
	var dir string
	root := &cobra.Command{
		Use:          "gendoc",
		Short:        "Generate vsign's help docs",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return doc.GenMarkdownTree(cli.New(), dir)
		},
	}
	root.Flags().StringVarP(&dir, "dir", "d", "doc", "Path to directory in which to generate docs")
	if err := root.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

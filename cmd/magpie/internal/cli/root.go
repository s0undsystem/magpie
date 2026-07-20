package cli

import (
	"github.com/harborproject/magpie/internal/version"
	"github.com/spf13/cobra"
)

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "magpie [domain]",
		Short: "magpie collects what a domain leaves out in the open",
		Long: "magpie is a passive, read-only reconnaissance tool that maps and\n" +
			"validates the /.well-known/ directory of a domain.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.Args = cobra.MaximumNArgs(1)
	root.RunE = runScan

	addScanFlags(root)

	root.AddCommand(newRegistryCmd())
	root.AddCommand(newExplainCmd())
	root.AddCommand(newDoctorCmd())

	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printBanner(cmd.OutOrStdout())
		defaultHelp(cmd, args)
	})

	return root
}

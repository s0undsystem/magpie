package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "explain [finding-id]",
		Short: "Print a longform explanation of a finding ID (or every ID with --all)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				return fmt.Errorf("explain --all is not implemented yet")
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			return fmt.Errorf("explain %s is not implemented yet", args[0])
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "print every finding ID")
	return cmd
}

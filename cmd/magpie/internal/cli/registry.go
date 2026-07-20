package cli

import (
	"fmt"

	"github.com/s0undsystem/magpie/internal/registry"
	"github.com/spf13/cobra"
)

func newRegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Inspect and update the IANA Well-Known URI Registry cache",
	}
	cmd.AddCommand(newRegistryListCmd())
	cmd.AddCommand(newRegistryUpdateCmd())
	return cmd
}

func newRegistryListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Print every documented well-known path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := registry.Load()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, e := range reg.Entries {
				fmt.Fprintf(out, "%-45s %-10s %s\n", e.FullPath(), e.Status, e.Reference)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d paths (source: %s)\n", len(reg.Entries), reg.Source)
			return nil
		},
	}
}

func newRegistryUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Fetch the current IANA registry and refresh the local cache in ~/.magpie/",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("registry update is not implemented yet")
		},
	}
}

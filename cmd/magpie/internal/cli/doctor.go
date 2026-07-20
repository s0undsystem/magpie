package cli

import (
	"fmt"
	"net"
	"os"

	"github.com/harborproject/magpie/internal/registry"
	"github.com/harborproject/magpie/internal/version"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check local setup: registry cache, config permissions, connectivity, DNS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ok := true

			fmt.Fprintf(out, "version: %s\n", version.Version)

			exists, path, age, err := registry.CacheInfo()
			switch {
			case err != nil:
				ok = false
				fmt.Fprintf(out, "[FAIL] registry cache: %v\n", err)
			case exists:
				fmt.Fprintf(out, "[ OK ] registry cache: %s (age %s)\n", path, age.Round(1e9))
			default:
				fmt.Fprintf(out, "[ OK ] registry cache: none (using embedded registry)\n")
			}

			dir, err := registry.CacheDir()
			if err != nil {
				ok = false
				fmt.Fprintf(out, "[FAIL] config directory: %v\n", err)
			} else if info, statErr := os.Stat(dir); statErr != nil {
				ok = false
				fmt.Fprintf(out, "[FAIL] config directory %s: %v\n", dir, statErr)
			} else {
				fmt.Fprintf(out, "[ OK ] config directory: %s (mode %s)\n", dir, info.Mode())
			}

			if _, err := net.LookupHost("www.iana.org"); err != nil {
				ok = false
				fmt.Fprintf(out, "[FAIL] DNS resolution: %v\n", err)
			} else {
				fmt.Fprintf(out, "[ OK ] DNS resolution\n")
			}

			conn, err := net.DialTimeout("tcp", "www.iana.org:443", 5e9)
			if err != nil {
				ok = false
				fmt.Fprintf(out, "[FAIL] outbound connectivity: %v\n", err)
			} else {
				conn.Close()
				fmt.Fprintf(out, "[ OK ] outbound connectivity\n")
			}

			if !ok {
				return fmt.Errorf("doctor found problems")
			}
			return nil
		},
	}
}

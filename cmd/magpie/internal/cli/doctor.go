package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/s0undsystem/magpie/internal/registry"
	"github.com/s0undsystem/magpie/internal/version"
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
			switch {
			case err != nil:
				ok = false
				fmt.Fprintf(out, "[FAIL] config directory: %v\n", err)
			default:
				probe := filepath.Join(dir, ".doctor-write-test")
				if writeErr := os.WriteFile(probe, []byte("ok"), 0o644); writeErr != nil {
					ok = false
					fmt.Fprintf(out, "[FAIL] config directory %s is not writable: %v\n", dir, writeErr)
				} else {
					os.Remove(probe)
					fmt.Fprintf(out, "[ OK ] config directory: %s (writable)\n", dir)
				}
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

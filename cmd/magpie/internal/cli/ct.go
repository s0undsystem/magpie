package cli

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/harborproject/magpie/internal/ct"
	"github.com/harborproject/magpie/internal/orchestrate"
)

func runCT(cmd *cobra.Command, host string, opts orchestrate.Options) error {
	stderr := cmd.ErrOrStderr()
	fmt.Fprintln(stderr, "querying crt.sh (public certificate transparency logs) for subdomains; no enumeration or probing is performed")

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}

	res, err := ct.Lookup(cmd.Context(), client, host, scan.ctLimit)
	if err != nil {
		return fmt.Errorf("certificate transparency lookup failed: %w", err)
	}

	if res.Truncated {
		fmt.Fprintf(stderr, "found more than %d subdomains; capped at %d (see --ct-limit)\n", scan.ctLimit, scan.ctLimit)
	}
	fmt.Fprintf(stderr, "found %d subdomain(s) via crt.sh; scanning %s plus discovered subdomains\n", len(res.Subdomains), host)

	hosts := append([]string{host}, res.Subdomains...)
	return scanAndRender(cmd, hosts, opts)
}

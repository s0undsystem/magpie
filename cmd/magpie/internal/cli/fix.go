package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/harborproject/magpie/internal/fix"
	"github.com/harborproject/magpie/internal/orchestrate"
	scanpkg "github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

// runFix implements --fix: scan host, pick the single most relevant fixable
// artifact, and print only that artifact's corrected content to stdout —
// nothing else, so `magpie example.org --fix > security.txt` works cleanly.
// All explanatory text goes to stderr. magpie never writes to host itself;
// this only prints what a human could choose to publish.
//
// Priority: a broken or missing security.txt is fixed first (it's the
// artifact the --fix examples in the spec redirect straight to a file), then
// an inactive mta-sts.txt DNS record, since publishing corrected security.txt
// content and a DNS record value in the same stream would produce a file
// that's neither.
func runFix(cmd *cobra.Command, host string, opts orchestrate.Options) error {
	raw, err := orchestrate.RunRaw(cmd.Context(), host, opts)
	if err != nil {
		return err
	}
	stderr := cmd.ErrOrStderr()
	stdout := cmd.OutOrStdout()
	now := time.Now()

	sectxt := findResult(raw.Results, "security.txt")
	sectxtOut := raw.Outputs["security.txt"]

	if needsSecurityTxtFix(sectxt, sectxtOut) {
		var existingBody []byte
		if sectxt != nil && sectxt.Presence == scanpkg.PresencePresent {
			existingBody = sectxt.Body
		}
		fmt.Fprintln(stderr, "security.txt is missing or invalid; printing a corrected file to stdout.")
		fmt.Fprintln(stderr, "Review the TODO-marked lines, then publish at /.well-known/security.txt.")
		fmt.Fprint(stdout, fix.SecurityTxt(host, existingBody, now))
		return nil
	}

	if mtasts, ok := raw.Outputs["mta-sts.txt"]; ok {
		if mtasts.Facts["mode"] != "" && mtasts.Facts["mta_sts_dns_txt_present"] == "false" {
			fmt.Fprintln(stderr, "mta-sts.txt is published but its DNS TXT activation record is missing.")
			fmt.Fprintf(stderr, "Publish this as a TXT record at _mta-sts.%s:\n", host)
			fmt.Fprintln(stdout, fix.MTASTSDNSRecord(now))
			return nil
		}
	}

	fmt.Fprintln(stderr, "nothing to fix: security.txt is valid and mta-sts.txt (if present) is activated.")
	return nil
}

// needsSecurityTxtFix reports whether security.txt is missing, unreachable,
// or has a validator finding --fix can correct (missing/malformed/expired
// required fields).
func needsSecurityTxtFix(r *scanpkg.Result, out validate.Output) bool {
	if r == nil || r.Presence != scanpkg.PresencePresent {
		return true
	}
	for _, f := range out.Findings {
		switch f.ID {
		case "SECTXT-001", "SECTXT-002", "SECTXT-003", "SECTXT-004":
			return true
		}
	}
	return false
}

func findResult(results []scanpkg.Result, path string) *scanpkg.Result {
	for i := range results {
		if results[i].Path == path {
			return &results[i]
		}
	}
	return nil
}

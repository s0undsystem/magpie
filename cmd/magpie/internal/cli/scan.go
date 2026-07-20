package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// scanFlags holds the flags shared by the single-domain scan invocation.
// Most of these are wired up in later build steps; they are declared now so
// the CLI surface and --help output are stable from the start.
type scanFlags struct {
	file          string
	concurrency   int
	timeoutSecs   int
	minSeverity   string
	minConfidence string
	category      []string
	rulesFile     string
	json          bool
	md            bool
	sarif         bool
	csv           bool
	compare       bool
	timing        bool
	noTimestamps  bool
	noColor       bool
	fix           bool
	save          bool
	diff          bool
	exitCode      bool
	watch         bool
	interval      string
	webhook       string
	ct            bool
	ctLimit       int
}

var scan scanFlags

func addScanFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&scan.file, "file", "f", "", "read newline-delimited domains from a file for batch mode")
	f.IntVar(&scan.concurrency, "concurrency", 10, "parallel requests per host")
	f.IntVar(&scan.timeoutSecs, "timeout", 10, "per-request timeout in seconds")
	f.StringVar(&scan.minSeverity, "min-severity", "info", "minimum severity to report (info, low, medium, high)")
	f.StringVar(&scan.minConfidence, "min-confidence", "inferred", "minimum confidence to report (certain, likely, inferred)")
	f.StringSliceVar(&scan.category, "category", nil, "only report findings in these categories")
	f.StringVar(&scan.rulesFile, "rules", "", "load additional or overriding correlation rules from this file")
	f.BoolVar(&scan.json, "json", false, "emit structured JSON output")
	f.BoolVar(&scan.md, "md", false, "emit a markdown report")
	f.BoolVar(&scan.sarif, "sarif", false, "emit SARIF 2.1.0 output")
	f.BoolVar(&scan.csv, "csv", false, "emit a flat CSV summary row (batch mode)")
	f.BoolVar(&scan.compare, "compare", false, "render results alongside the reference corpus")
	f.BoolVar(&scan.timing, "timing", false, "show per-path timing in terminal output")
	f.BoolVar(&scan.noTimestamps, "no-timestamps", false, "suppress timestamps for deterministic output")
	f.BoolVar(&scan.noColor, "no-color", false, "disable colored terminal output")
	f.BoolVar(&scan.fix, "fix", false, "print corrected artifacts to stdout instead of a report")
	f.BoolVar(&scan.save, "save", false, "save a snapshot of this run under ~/.magpie/snapshots/")
	f.BoolVar(&scan.diff, "diff", false, "compare against the most recent snapshot")
	f.BoolVar(&scan.exitCode, "exit-code", false, "with --diff, exit non-zero if a new medium+ finding appeared")
	f.BoolVar(&scan.watch, "watch", false, "run continuously, re-checking on --interval")
	f.StringVar(&scan.interval, "interval", "6h", "re-check interval for --watch")
	f.StringVar(&scan.webhook, "webhook", "", "POST the change set as JSON to this URL on each --watch tick")
	f.BoolVar(&scan.ct, "ct", false, "expand scan to subdomains found via public certificate transparency logs (crt.sh); no enumeration or probing")
	f.IntVar(&scan.ctLimit, "ct-limit", 50, "maximum number of CT-discovered subdomains to scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	if scan.file != "" {
		return fmt.Errorf("batch mode (-f) is not implemented yet")
	}
	if len(args) == 0 {
		return cmd.Help()
	}
	return fmt.Errorf("scanning %s is not implemented yet", args[0])
}

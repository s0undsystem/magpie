package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/orchestrate"
	"github.com/harborproject/magpie/internal/render"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/snapshot"
	"github.com/harborproject/magpie/internal/version"
)

// scanFlags holds the flags shared by the single-domain scan invocation.
// Most of these are wired up in later build steps; they are declared now so
// the CLI surface and --help output are stable from the start.
type scanFlags struct {
	file              string
	concurrency       int
	globalConcurrency int
	timeoutSecs       int
	minSeverity       string
	minConfidence     string
	category          []string
	rulesFile         string
	json              bool
	md                bool
	sarif             bool
	csv               bool
	compare           bool
	timing            bool
	noTimestamps      bool
	noColor           bool
	fix               bool
	save              bool
	diff              bool
	exitCode          bool
	watch             bool
	interval          string
	webhook           string
	ct                bool
	ctLimit           int
}

var scan scanFlags

func addScanFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&scan.file, "file", "f", "", "read newline-delimited domains from a file for batch mode")
	f.IntVar(&scan.concurrency, "concurrency", 10, "parallel requests per host")
	f.IntVar(&scan.globalConcurrency, "global-concurrency", 5, "parallel domains scanned at once in batch mode (-f), independent of --concurrency")
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
	f.BoolVar(&scan.ct, "ct", false, "off by default. Expand the scan to subdomains found in public certificate transparency logs (crt.sh). This only reads certificates already issued and logged by public CAs; magpie performs no DNS brute forcing, wordlist enumeration, or probing to find subdomains.")
	f.IntVar(&scan.ctLimit, "ct-limit", 50, "with --ct, cap on how many discovered subdomains to scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	if scan.file != "" {
		return runBatch(cmd, scan.file)
	}
	if len(args) == 0 {
		return cmd.Help()
	}
	host := args[0]

	filter, err := buildFilter()
	if err != nil {
		return err
	}

	opts, err := buildOrchestrateOptions()
	if err != nil {
		return err
	}

	if scan.fix {
		return runFix(cmd, host, opts)
	}

	if scan.watch {
		return runWatch(cmd, host, opts)
	}

	if scan.ct {
		return runCT(cmd, host, opts)
	}

	rep, err := orchestrate.Run(cmd.Context(), host, opts)
	if err != nil {
		return err
	}

	renderOpts := render.Options{
		NoColor:      scan.noColor || os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stdout.Fd()),
		NoTimestamps: scan.noTimestamps,
		Timing:       scan.timing,
		Compare:      scan.compare,
		Filter:       filter,
	}

	out := cmd.OutOrStdout()

	if scan.diff {
		return runDiff(cmd, rep)
	}

	if scan.save {
		if _, err := snapshot.Save(rep); err != nil {
			return fmt.Errorf("saving snapshot: %w", err)
		}
	}

	switch {
	case scan.json:
		return render.JSON(out, rep, renderOpts)
	case scan.md:
		return render.Markdown(out, rep, renderOpts)
	case scan.csv:
		return render.CSV(out, []report.Report{rep}, renderOpts)
	case scan.sarif:
		return render.SARIF(out, rep, renderOpts)
	default:
		return render.Terminal(out, rep, renderOpts)
	}
}

// runDiff implements --diff: compare rep against the most recent saved
// snapshot for its domain and print only what changed. If --save was also
// passed, the previous snapshot is loaded before the new one is written so
// the diff isn't comparing rep against itself.
func runDiff(cmd *cobra.Command, rep report.Report) error {
	prev, ok, err := snapshot.Latest(rep.Domain)
	if err != nil {
		return fmt.Errorf("loading previous snapshot: %w", err)
	}

	if scan.save {
		if _, err := snapshot.Save(rep); err != nil {
			return fmt.Errorf("saving snapshot: %w", err)
		}
	}

	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), "no previous snapshot found; nothing to diff against (use --save to start tracking)")
		return nil
	}

	d := snapshot.Compute(prev, rep)
	fmt.Fprint(cmd.OutOrStdout(), d.RenderText())

	if scan.exitCode && d.HasNewMediumOrHigher() {
		os.Exit(1)
	}
	return nil
}

// buildOrchestrateOptions assembles orchestrate.Options from scan flags,
// shared by single-domain scans, batch mode, and --ct.
func buildOrchestrateOptions() (orchestrate.Options, error) {
	var rulesOverlay []byte
	if scan.rulesFile != "" {
		data, err := os.ReadFile(scan.rulesFile)
		if err != nil {
			return orchestrate.Options{}, fmt.Errorf("reading --rules file: %w", err)
		}
		rulesOverlay = data
	}

	return orchestrate.Options{
		Concurrency:  scan.concurrency,
		RatePerSec:   float64(scan.concurrency),
		Timeout:      time.Duration(scan.timeoutSecs) * time.Second,
		UserAgent:    version.UserAgent(""),
		MaxRedirects: 5,
		RulesOverlay: rulesOverlay,
	}, nil
}

func buildFilter() (finding.Filter, error) {
	minSev, err := finding.ParseSeverity(scan.minSeverity)
	if err != nil {
		return finding.Filter{}, err
	}
	minConf, err := finding.ParseConfidence(scan.minConfidence)
	if err != nil {
		return finding.Filter{}, err
	}
	var cats []finding.Category
	for _, c := range scan.category {
		cat, err := finding.ParseCategory(c)
		if err != nil {
			return finding.Filter{}, err
		}
		cats = append(cats, cat)
	}
	return finding.Filter{MinSeverity: minSev, MinConfidence: minConf, Categories: cats}, nil
}

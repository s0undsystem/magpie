package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/s0undsystem/magpie/internal/orchestrate"
	"github.com/s0undsystem/magpie/internal/render"
	"github.com/s0undsystem/magpie/internal/report"
)

type batchResult struct {
	Domain string
	Report report.Report
	Err    error
}

func runBatch(cmd *cobra.Command, path string) error {
	domains, err := readDomainsFile(path)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains found in %s", path)
	}

	opts, err := buildOrchestrateOptions()
	if err != nil {
		return err
	}
	return scanAndRender(cmd, domains, opts)
}

func scanAndRender(cmd *cobra.Command, hosts []string, opts orchestrate.Options) error {
	filter, err := buildFilter()
	if err != nil {
		return err
	}

	if !scan.json && !scan.csv && !scan.noBanner {
		printBanner(cmd.OutOrStdout())
	}

	results := make([]batchResult, len(hosts))
	sem := make(chan struct{}, scan.globalConcurrency)
	var wg sync.WaitGroup

	stderr := cmd.ErrOrStderr()
	progress := newProgress(stderr, len(hosts))

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep, err := orchestrate.Run(cmd.Context(), host, opts)
			results[i] = batchResult{Domain: host, Report: rep, Err: err}
			progress.tick(host, err)
		}(i, host)
	}
	wg.Wait()
	progress.done()

	renderOpts := render.Options{
		NoColor:      scan.noColor || os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stdout.Fd()),
		NoTimestamps: scan.noTimestamps,
		Timing:       scan.timing,
		Filter:       filter,
	}

	out := cmd.OutOrStdout()
	switch {
	case scan.csv:
		var reports []report.Report
		for _, r := range results {
			if r.Err == nil {
				reports = append(reports, r.Report)
			}
		}
		return render.CSV(out, reports, renderOpts)
	case scan.json:
		for _, r := range results {
			if r.Err != nil {
				fmt.Fprintf(out, "{\"domain\":%q,\"error\":%q}\n", r.Domain, r.Err.Error())
				continue
			}
			if err := render.JSONLine(out, r.Report, renderOpts); err != nil {
				return err
			}
		}
		return nil
	default:
		for i, r := range results {
			if i > 0 {
				fmt.Fprintln(out)
			}
			if r.Err != nil {
				fmt.Fprintf(out, "%s: error: %v\n", r.Domain, r.Err)
				continue
			}
			if err := render.Terminal(out, r.Report, renderOpts); err != nil {
				return err
			}
		}
		return nil
	}
}

func readDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return domains, nil
}

type progress struct {
	w      io.Writer
	total  int
	tty    bool
	done32 int32
	mu     sync.Mutex
}

func newProgress(w io.Writer, total int) *progress {
	tty := false
	if f, ok := w.(*os.File); ok {
		tty = isatty.IsTerminal(f.Fd())
	}
	return &progress{w: w, total: total, tty: tty}
}

func (p *progress) tick(domain string, err error) {
	n := atomic.AddInt32(&p.done32, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tty {
		fmt.Fprintf(p.w, "\rscanned %d/%d domains", n, p.total)
		return
	}
	status := "ok"
	if err != nil {
		status = "error: " + err.Error()
	}
	fmt.Fprintf(p.w, "[%d/%d] %s: %s\n", n, p.total, domain, status)
}

func (p *progress) done() {
	if p.tty {
		fmt.Fprintln(p.w)
	}
}

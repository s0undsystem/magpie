package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/s0undsystem/magpie/internal/orchestrate"
	"github.com/s0undsystem/magpie/internal/snapshot"
)

func runWatch(cmd *cobra.Command, host string, opts orchestrate.Options) error {
	interval, err := time.ParseDuration(scan.interval)
	if err != nil {
		return fmt.Errorf("invalid --interval %q: %w", scan.interval, err)
	}
	if interval <= 0 {
		return fmt.Errorf("--interval must be positive, got %s", interval)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	stderr := cmd.ErrOrStderr()
	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stderr, "watching %s every %s (press Ctrl+C to stop)\n", host, interval)

	for {
		if err := watchTick(ctx, host, opts, stdout, stderr); err != nil && ctx.Err() == nil {
			fmt.Fprintf(stderr, "scan error: %v\n", err)
		}

		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "stopping watch")
			return nil
		case <-time.After(interval):
		}
	}
}

func watchTick(ctx context.Context, host string, opts orchestrate.Options, stdout, stderr io.Writer) error {
	rep, err := orchestrate.Run(ctx, host, opts)
	if err != nil {
		return err
	}

	prev, ok, err := snapshot.Latest(host)
	if err != nil {
		return err
	}

	if ok {
		d := snapshot.Compute(prev, rep)
		if d.HasChanges() {
			fmt.Fprint(stdout, d.RenderText())
			if scan.webhook != "" {
				if err := postWebhook(ctx, scan.webhook, d); err != nil {
					fmt.Fprintf(stderr, "webhook delivery failed: %v\n", err)
				}
			}
		}
	} else {
		fmt.Fprintln(stderr, "first scan; establishing baseline snapshot")
	}

	_, err = snapshot.Save(rep)
	return err
}

func postWebhook(ctx context.Context, url string, d snapshot.Diff) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

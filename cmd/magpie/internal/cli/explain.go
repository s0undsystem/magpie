package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/s0undsystem/magpie/internal/correlate"
	"github.com/s0undsystem/magpie/internal/explain"
)

func newExplainCmd() *cobra.Command {
	var all bool
	var asMarkdown bool
	cmd := &cobra.Command{
		Use:   "explain [finding-id]",
		Short: "Print a longform explanation of a finding ID (or every ID with --all)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			docs := allDocs()

			if all {
				if asMarkdown {
					return explain.RenderMarkdown(out, docs)
				}
				return explain.RenderAllText(out, docs)
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			id := args[0]
			for _, d := range docs {
				if d.ID == id {
					return explain.RenderText(out, d)
				}
			}
			return fmt.Errorf("unknown finding id %q (see `magpie explain --all`)", id)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "print every finding ID")
	cmd.Flags().BoolVar(&asMarkdown, "md", false, "with --all, emit markdown suitable for a docs site")
	return cmd
}

func allDocs() []explain.Doc {
	docs := explain.All()

	for _, r := range correlate.NewEngine().Rules() {
		docs = append(docs, explain.Doc{
			ID:          r.ID,
			Severity:    r.Severity,
			Confidence:  r.Confidence,
			Category:    r.Category,
			Message:     r.Message,
			SpecRef:     r.SpecRef,
			Explanation: r.Explanation,
		})
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	return docs
}

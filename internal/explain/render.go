package explain

import (
	"fmt"
	"io"
	"strings"
)

func RenderText(w io.Writer, d Doc) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", d.ID)
	fmt.Fprintf(&b, "  severity:   %s\n", d.Severity)
	fmt.Fprintf(&b, "  confidence: %s\n", d.Confidence)
	fmt.Fprintf(&b, "  category:   %s\n", d.Category)
	fmt.Fprintf(&b, "  summary:    %s\n", d.Message)
	if d.SpecRef != "" {
		fmt.Fprintf(&b, "  spec:       %s\n", d.SpecRef)
	}
	b.WriteString("\n")
	b.WriteString(wrap(d.Explanation, 78))
	b.WriteString("\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

func RenderAllText(w io.Writer, docs []Doc) error {
	var b strings.Builder
	for i, d := range docs {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		var doc strings.Builder
		if err := RenderText(&doc, d); err != nil {
			return err
		}
		b.WriteString(doc.String())
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

func RenderMarkdown(w io.Writer, docs []Doc) error {
	var b strings.Builder
	b.WriteString("# magpie finding reference\n\n")
	for _, d := range docs {
		fmt.Fprintf(&b, "## %s\n\n", d.ID)
		fmt.Fprintf(&b, "- **Severity**: %s\n", d.Severity)
		fmt.Fprintf(&b, "- **Confidence**: %s\n", d.Confidence)
		fmt.Fprintf(&b, "- **Category**: %s\n", d.Category)
		fmt.Fprintf(&b, "- **Summary**: %s\n", d.Message)
		if d.SpecRef != "" {
			fmt.Fprintf(&b, "- **Spec**: %s\n", d.SpecRef)
		}
		b.WriteString("\n")
		b.WriteString(d.Explanation)
		b.WriteString("\n\n")
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

func wrap(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		if i > 0 {
			if lineLen+1+len(word) > width {
				b.WriteString("\n")
				lineLen = 0
			} else {
				b.WriteString(" ")
				lineLen++
			}
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	return b.String()
}

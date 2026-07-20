package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"

	"github.com/harborproject/magpie/internal/banner"
)

var bannerColor = lipgloss.Color("6")

func stdoutIsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if f, ok := w.(*os.File); ok {
		return isatty.IsTerminal(f.Fd())
	}
	return false
}

func printBanner(w io.Writer) {
	renderer := lipgloss.NewRenderer(w)
	if !stdoutIsColor(w) {
		renderer.SetColorProfile(termenv.Ascii)
	}
	style := renderer.NewStyle().Foreground(bannerColor)
	fmt.Fprintln(w, style.Render(banner.Bird+banner.Wordmark))
}

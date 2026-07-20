package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

// bannerArt is magpie's mascot, shown above --help output.
const bannerArt = `
      .---.        .-----------
     /     \  __  /    ------
    / /     \(  )/    -----
   //////   ' \/ ` + "`" + `   ---
  //// / // :    : ---
 // /   /  /` + "`" + `    '--
//          //..\\
       ====UU====UU====
           '//||\\` + "`" + `
             ''` + "``" + `
`

// bannerWordmark is the magpie wordmark, shown beneath bannerArt.
const bannerWordmark = `
 __   __  _______  _______  _______  ___   _______
|  |_|  ||   _   ||       ||       ||   | |       |
|       ||  |_|  ||    ___||    _  ||   | |    ___|
|       ||       ||   | __ |   |_| ||   | |   |___
|       ||       ||   ||  ||    ___||   | |    ___|
| ||_|| ||   _   ||   |_| ||   |    |   | |   |___
|_|   |_||__| |__||_______||___|    |___| |_______|
`

// bannerColor is the teal used across the tool for headings, matched here
// for the mascot banner.
var bannerColor = lipgloss.Color("6")

// printBanner writes the mascot and wordmark to w, in teal when color is
// appropriate for the destination (a real TTY, no NO_COLOR, not explicitly
// disabled).
func printBanner(w io.Writer) {
	renderer := lipgloss.NewRenderer(w)
	noColor := os.Getenv("NO_COLOR") != ""
	if f, ok := w.(*os.File); ok {
		noColor = noColor || !isatty.IsTerminal(f.Fd())
	}
	if noColor {
		renderer.SetColorProfile(termenv.Ascii)
	}
	style := renderer.NewStyle().Foreground(bannerColor)
	fmt.Fprintln(w, style.Render(bannerArt+bannerWordmark))
}

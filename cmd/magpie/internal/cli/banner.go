package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

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

const bannerWordmark = `
 __   __  _______  _______  _______  ___   _______
|  |_|  ||   _   ||       ||       ||   | |       |
|       ||  |_|  ||    ___||    _  ||   | |    ___|
|       ||       ||   | __ |   |_| ||   | |   |___
|       ||       ||   ||  ||    ___||   | |    ___|
| ||_|| ||   _   ||   |_| ||   |    |   | |   |___
|_|   |_||__| |__||_______||___|    |___| |_______|
`

var bannerColor = lipgloss.Color("6")

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

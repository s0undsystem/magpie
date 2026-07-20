package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

type spinner struct {
	w       io.Writer
	message string
	tty     bool

	mu      sync.Mutex
	stopCh  chan struct{}
	doneCh  chan struct{}
	started bool
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func newSpinner(w io.Writer, message string) *spinner {
	tty := false
	if f, ok := w.(*os.File); ok {
		tty = isatty.IsTerminal(f.Fd())
	}
	return &spinner{w: w, message: message, tty: tty}
}

func (s *spinner) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true

	if !s.tty {
		fmt.Fprintln(s.w, s.message)
		return
	}

	renderer := lipgloss.NewRenderer(s.w)
	if os.Getenv("NO_COLOR") != "" {
		renderer.SetColorProfile(termenv.Ascii)
	}
	style := renderer.NewStyle().Foreground(bannerColor)

	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	go func() {
		defer close(s.doneCh)
		ticker := time.NewTicker(90 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				frame := style.Render(spinnerFrames[i%len(spinnerFrames)])
				fmt.Fprintf(s.w, "\r%s %s", frame, s.message)
				i++
			}
		}
	}()
}

func (s *spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return
	}
	s.started = false

	if !s.tty {
		return
	}
	close(s.stopCh)
	<-s.doneCh
	clear := strings.Repeat(" ", len(s.message)+4)
	fmt.Fprintf(s.w, "\r%s\r", clear)
}

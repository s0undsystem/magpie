package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDomainsFileSkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := "# a comment\nexample.org\n\n  github.com  \n# another\nexample.net\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readDomainsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.org", "github.com", "example.net"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadDomainsFileMissingFile(t *testing.T) {
	if _, err := readDomainsFile("/nonexistent/path/domains.txt"); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestReadDomainsFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readDomainsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestProgressNonTTYWritesOneLinePerDomain(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(&buf, 2) // buf is not *os.File, so tty=false
	p.tick("example.org", nil)
	p.tick("example.net", nil)
	p.done()

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "example.org") || !strings.Contains(lines[0], "ok") {
		t.Errorf("line 0 = %q", lines[0])
	}
}

func TestProgressReportsErrors(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(&buf, 1)
	p.tick("example.org", errUnreachable)
	out := buf.String()
	if !strings.Contains(out, "error") {
		t.Errorf("expected error status in output, got %q", out)
	}
}

var errUnreachable = &testError{"host unreachable"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

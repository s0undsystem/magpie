package snapshot

import (
	"testing"
	"time"

	"github.com/harborproject/magpie/internal/report"
)

// withTempHome redirects ~/.magpie (via $HOME) to a temp directory so tests
// never touch the real user config.
func withTempHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestSaveAndLatest(t *testing.T) {
	withTempHome(t)
	rep := report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	path, err := Save(rep)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected a non-empty snapshot path")
	}

	loaded, ok, err := Latest("example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a snapshot to be found")
	}
	if loaded.Domain != "example.org" {
		t.Errorf("loaded.Domain = %q", loaded.Domain)
	}
}

func TestLatestNoSnapshotsOK(t *testing.T) {
	withTempHome(t)
	_, ok, err := Latest("never-scanned.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false when no snapshot exists")
	}
}

func TestLatestReturnsMostRecent(t *testing.T) {
	withTempHome(t)
	older := report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SchemaVersion: 1}
	newer := report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), SchemaVersion: 2}

	if _, err := Save(older); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(newer); err != nil {
		t.Fatal(err)
	}

	loaded, ok, err := Latest("example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a snapshot")
	}
	if loaded.SchemaVersion != 2 {
		t.Errorf("expected the newer snapshot (schema 2), got schema %d", loaded.SchemaVersion)
	}
}

func TestListSortedChronologically(t *testing.T) {
	withTempHome(t)
	Save(report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)})
	Save(report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	Save(report.Report{Domain: "example.org", ScannedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)})

	names, err := List("example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Fatalf("got %d snapshots, want 3", len(names))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("List() not sorted chronologically: %v", names)
		}
	}
}

func TestSnapshotsIsolatedPerDomain(t *testing.T) {
	withTempHome(t)
	Save(report.Report{Domain: "a.example.org", ScannedAt: time.Now()})
	_, ok, err := Latest("b.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected no snapshot for a domain that was never scanned")
	}
}

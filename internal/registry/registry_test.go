package registry

import (
	"sort"
	"testing"
)

func TestLoadEmbeddedIsSorted(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(reg.Entries) == 0 {
		t.Fatal("expected non-empty registry")
	}
	if !sort.SliceIsSorted(reg.Entries, func(i, j int) bool {
		return reg.Entries[i].Path < reg.Entries[j].Path
	}) {
		t.Error("registry entries are not sorted by path")
	}
}

func TestLoadDeterministic(t *testing.T) {
	a, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != len(b.Entries) {
		t.Fatal("two loads produced different entry counts")
	}
	for i := range a.Entries {
		if a.Entries[i] != b.Entries[i] {
			t.Fatalf("entry %d differs between loads: %+v vs %+v", i, a.Entries[i], b.Entries[i])
		}
	}
}

func TestKnownPathsPresent(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"security.txt",
		"openid-configuration",
		"mta-sts.txt",
		"assetlinks.json",
		"apple-app-site-association",
		"change-password",
		"acme-challenge",
		"oauth-authorization-server",
		"matrix/server",
		"matrix/client",
	}
	have := map[string]bool{}
	for _, e := range reg.Entries {
		have[e.Path] = true
	}
	for _, p := range want {
		if !have[p] {
			t.Errorf("expected registry to contain path %q", p)
		}
	}
}

func TestFullPath(t *testing.T) {
	e := Entry{Path: "security.txt"}
	if got := e.FullPath(); got != "/.well-known/security.txt" {
		t.Errorf("FullPath() = %q", got)
	}
}

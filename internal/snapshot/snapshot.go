// Package snapshot saves and loads point-in-time report.Report snapshots
// under ~/.magpie/snapshots/<domain>/, and diffs two snapshots to answer
// "what changed since last time."
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/harborproject/magpie/internal/registry"
	"github.com/harborproject/magpie/internal/report"
)

// timestampLayout is chosen to sort lexicographically in chronological
// order, so "most recent snapshot" is just "last name after sorting."
const timestampLayout = "20060102T150405Z"

// Dir returns ~/.magpie/snapshots/<domain>, creating it if necessary.
func Dir(domain string) (string, error) {
	cacheDir, err := registry.CacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cacheDir, "snapshots", domain)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Save writes rep as a new timestamped snapshot file and returns its path.
func Save(rep report.Report) (string, error) {
	dir, err := Dir(rep.Domain)
	if err != nil {
		return "", err
	}
	name := rep.ScannedAt.UTC().Format(timestampLayout) + ".json"
	path := filepath.Join(dir, name)

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", fmt.Errorf("snapshot: marshaling report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("snapshot: writing %s: %w", path, err)
	}
	return path, nil
}

// List returns every snapshot filename for domain, sorted chronologically
// (oldest first).
func List(domain string) ([]string, error) {
	dir, err := Dir(domain)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Latest loads the most recent snapshot for domain. ok is false if no
// snapshot exists yet.
func Latest(domain string) (rep report.Report, ok bool, err error) {
	names, err := List(domain)
	if err != nil {
		return report.Report{}, false, err
	}
	if len(names) == 0 {
		return report.Report{}, false, nil
	}
	dir, err := Dir(domain)
	if err != nil {
		return report.Report{}, false, err
	}
	path := filepath.Join(dir, names[len(names)-1])
	data, err := os.ReadFile(path)
	if err != nil {
		return report.Report{}, false, err
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return report.Report{}, false, fmt.Errorf("snapshot: parsing %s: %w", path, err)
	}
	return rep, true, nil
}

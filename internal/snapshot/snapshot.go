package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/s0undsystem/magpie/internal/registry"
	"github.com/s0undsystem/magpie/internal/report"
)

const timestampLayout = "20060102T150405Z"

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

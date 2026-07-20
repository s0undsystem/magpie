package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

//go:embed iana_wellknown.json
var embeddedRegistryJSON []byte

type Entry struct {
	Path        string `json:"path"`
	Reference   string `json:"reference"`
	Status      string `json:"status"`
	ContentType string `json:"content_type"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

func (e Entry) FullPath() string {
	return "/.well-known/" + e.Path
}

type Registry struct {
	Entries []Entry `json:"entries"`
	Source  string  `json:"source"`
	Updated string  `json:"updated,omitempty"`
}

func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".magpie")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func cachePath() (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "registry_cache.json"), nil
}

func Load() (*Registry, error) {
	reg, err := loadEmbedded()
	if err != nil {
		return nil, err
	}

	path, err := cachePath()
	if err != nil {

		return reg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return reg, nil
	}
	var cached Registry
	if err := json.Unmarshal(data, &cached); err != nil {
		return reg, nil
	}
	cached.Source = path
	sortEntries(cached.Entries)
	return &cached, nil
}

func loadEmbedded() (*Registry, error) {
	var reg Registry
	if err := json.Unmarshal(embeddedRegistryJSON, &reg); err != nil {
		return nil, fmt.Errorf("registry: parse embedded registry: %w", err)
	}
	reg.Source = "embedded"
	sortEntries(reg.Entries)
	return &reg, nil
}

func sortEntries(e []Entry) {
	sort.Slice(e, func(i, j int) bool { return e[i].Path < e[j].Path })
}

func SaveCache(reg *Registry) (string, error) {
	path, err := cachePath()
	if err != nil {
		return "", err
	}
	reg.Updated = time.Now().UTC().Format(time.RFC3339)
	sortEntries(reg.Entries)
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func CacheInfo() (exists bool, path string, age time.Duration, err error) {
	path, err = cachePath()
	if err != nil {
		return false, "", 0, err
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return false, path, 0, nil
	}
	return true, path, time.Since(info.ModTime()), nil
}

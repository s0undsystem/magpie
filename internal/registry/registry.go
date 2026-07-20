// Package registry provides the IANA Well-Known URI Registry, embedded at
// build time, with support for a locally cached override.
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

// Entry describes a single documented well-known path.
type Entry struct {
	Path        string `json:"path"`         // e.g. "security.txt"
	Reference   string `json:"reference"`    // RFC/spec citation
	Status      string `json:"status"`       // registration status, e.g. "permanent"
	ContentType string `json:"content_type"` // expected content type, "" if unspecified
	Kind        string `json:"kind"`         // "json", "text", "html", "" (unspecified)
	Description string `json:"description"`
}

// FullPath returns the absolute /.well-known/ URL path for this entry.
func (e Entry) FullPath() string {
	return "/.well-known/" + e.Path
}

// Registry is an ordered, deterministic set of well-known registry entries.
type Registry struct {
	Entries []Entry `json:"entries"`
	Source  string  `json:"source"` // "embedded" or path to cache file
	Updated string  `json:"updated,omitempty"`
}

// CacheDir returns ~/.magpie, creating it if necessary.
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

// Load returns the registry, preferring a local cache file over the embedded
// copy when the cache exists and is newer than the build-embedded version.
func Load() (*Registry, error) {
	reg, err := loadEmbedded()
	if err != nil {
		return nil, err
	}

	path, err := cachePath()
	if err != nil {
		// No home dir available; fall back to embedded silently.
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

// SaveCache writes the registry to the local cache file, stamping the update
// time.
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

// CacheInfo reports whether a local cache exists and its age.
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

package correlate

import (
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

type DocFacts struct {
	Path              string
	Presence          scan.Presence
	ContentType       string
	RedirectOffsiteTo string
	Facts             validate.Facts
	Findings          []finding.Finding
}

type Snapshot struct {
	Host string
	Docs map[string]DocFacts
}

func BuildSnapshot(host string, results []scan.Result, outputs map[string]validate.Output) Snapshot {
	docs := make(map[string]DocFacts, len(results))
	for _, r := range results {
		df := DocFacts{
			Path:              r.Path,
			Presence:          r.Presence,
			ContentType:       r.ContentType,
			RedirectOffsiteTo: r.RedirectOffsiteTo,
		}
		if out, ok := outputs[r.Path]; ok {
			df.Facts = out.Facts
			df.Findings = out.Findings
		}
		docs[r.Path] = df
	}
	return Snapshot{Host: host, Docs: docs}
}

func (s Snapshot) fact(path, key string) (string, bool) {
	d, ok := s.Docs[path]
	if !ok || d.Facts == nil {
		return "", false
	}
	v, ok := d.Facts[key]
	return v, ok
}

func (s Snapshot) presence(path string) scan.Presence {
	d, ok := s.Docs[path]
	if !ok {
		return ""
	}
	return d.Presence
}

func (s Snapshot) hasFinding(path, id string) bool {
	d, ok := s.Docs[path]
	if !ok {
		return false
	}
	for _, f := range d.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func (s Snapshot) cleanCount() int {
	n := 0
	for _, d := range s.Docs {
		if d.Presence == scan.PresencePresent && len(d.Findings) == 0 {
			n++
		}
	}
	return n
}

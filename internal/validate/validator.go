package validate

import (
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

type Facts map[string]string

type AuxFetcher func(url string) (*scan.Result, error)

type Context struct {
	Host string

	Result scan.Result

	Fetch AuxFetcher

	LookupTXT func(name string) ([]string, error)
}

type Output struct {
	Findings []finding.Finding
	Facts    Facts
}

type Validator interface {
	Path() string

	Validate(ctx Context) Output
}

var registry = map[string]Validator{}

func Register(v Validator) {
	if _, exists := registry[v.Path()]; exists {
		panic("validate: duplicate validator registered for path " + v.Path())
	}
	registry[v.Path()] = v
}

func Lookup(path string) (Validator, bool) {
	v, ok := registry[path]
	return v, ok
}

func finalURL(r scan.Result) string {
	if len(r.RedirectChain) > 0 {
		return r.RedirectChain[len(r.RedirectChain)-1]
	}
	return r.URL
}

func baseContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

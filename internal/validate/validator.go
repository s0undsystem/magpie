// Package validate defines the Validator plugin interface and the
// per-path implementations that inspect fetched well-known documents and
// produce structured findings.
package validate

import (
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

// Facts is a normalized set of string observations a validator extracts
// from a document. The inference layer and the correlation engine's
// generic disagreement rule (CORR-024) consume these instead of re-parsing
// raw content.
type Facts map[string]string

// AuxFetcher performs a single additional GET against a URL explicitly
// referenced inside already-fetched well-known content (for example a
// security.txt Encryption field pointing at a PGP key). It exists only to
// follow a pointer the target itself published; it must never be used to
// guess or enumerate paths.
type AuxFetcher func(url string) (*scan.Result, error)

// Context is everything a Validator needs to inspect one fetched
// well-known result.
type Context struct {
	// Host is the target host, e.g. "example.org".
	Host string
	// Result is the fetch outcome for this validator's path. Validators
	// are invoked regardless of Presence so they can react to absence or
	// soft404 when that itself is meaningful (e.g. change-password).
	Result scan.Result
	// Fetch performs a single auxiliary GET against an explicitly
	// referenced URL. It is nil when auxiliary fetches are disabled.
	Fetch AuxFetcher
	// LookupTXT resolves DNS TXT records for a name, used by validators
	// that cross-check a well-known document against DNS (e.g. mta-sts.txt
	// against _mta-sts.<host>). It is nil when DNS lookups are disabled.
	LookupTXT func(name string) ([]string, error)
}

// Output is what a Validator returns.
type Output struct {
	Findings []finding.Finding
	Facts    Facts
}

// Validator inspects one documented well-known path's fetched content and
// produces findings plus extracted facts. New validators are added as
// plugins by implementing this interface and registering with Register.
type Validator interface {
	// Path is the well-known registry path this validator owns, e.g.
	// "security.txt" (no leading /.well-known/).
	Path() string
	// Validate inspects ctx and returns findings and facts.
	Validate(ctx Context) Output
}

// registry is the set of built-in validators, keyed by registry path.
var registry = map[string]Validator{}

// Register adds a validator to the built-in set, keyed by its Path(). It
// panics on duplicate registration, which can only happen from a
// programming error at init time.
func Register(v Validator) {
	if _, exists := registry[v.Path()]; exists {
		panic("validate: duplicate validator registered for path " + v.Path())
	}
	registry[v.Path()] = v
}

// Lookup returns the registered validator for a well-known path, if any.
func Lookup(path string) (Validator, bool) {
	v, ok := registry[path]
	return v, ok
}

// finalURL returns the last URL in the result's redirect chain, or its
// originally requested URL if it was never redirected.
func finalURL(r scan.Result) string {
	if len(r.RedirectChain) > 0 {
		return r.RedirectChain[len(r.RedirectChain)-1]
	}
	return r.URL
}

// baseContentType strips any parameters (e.g. "; charset=utf-8") from a
// Content-Type header value.
func baseContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

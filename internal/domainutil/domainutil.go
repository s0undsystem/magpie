// Package domainutil provides a small, pragmatic helper for comparing
// registrable domains (eTLD+1). It is deliberately not a full Public
// Suffix List implementation — it recognizes a short curated list of common
// multi-label public suffixes and otherwise falls back to the last two
// labels. This is a known, documented limitation (see README): domains
// under less common multi-label suffixes not in the list below will be
// compared one label too coarsely.
package domainutil

import "strings"

var twoLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true,
	"co.jp": true, "co.in": true, "co.nz": true, "co.za": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.br": true, "com.cn": true, "com.mx": true,
}

// Registrable returns the registrable domain (eTLD+1) for host. Hosts that
// are bare IP addresses or already a single label are returned unchanged.
func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.IndexByte(host, ':'); i >= 0 { // strip a port, if present
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if len(labels) >= 3 && twoLabelSuffixes[lastTwo] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}

// SameRegistrable reports whether a and b share the same registrable
// domain.
func SameRegistrable(a, b string) bool {
	return Registrable(a) == Registrable(b)
}

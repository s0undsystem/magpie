package domainutil

import "strings"

var twoLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true,
	"co.jp": true, "co.in": true, "co.nz": true, "co.za": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.br": true, "com.cn": true, "com.mx": true,
}

func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.IndexByte(host, ':'); i >= 0 {
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

func SameRegistrable(a, b string) bool {
	return Registrable(a) == Registrable(b)
}

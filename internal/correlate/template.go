package correlate

import (
	"regexp"
	"strings"
)

var templateTokenRe = regexp.MustCompile(`\{\{([a-zA-Z0-9_.:/\-]+)\}\}`)

func renderTemplate(tmpl string, snap Snapshot) string {
	if tmpl == "" {
		return ""
	}
	return templateTokenRe.ReplaceAllStringFunc(tmpl, func(tok string) string {
		inner := tok[2 : len(tok)-2]
		switch {
		case inner == "host":
			return snap.Host
		case strings.HasPrefix(inner, "fact:"):
			rest := strings.TrimPrefix(inner, "fact:")
			i := strings.LastIndexByte(rest, '.')
			if i < 0 {
				return tok
			}
			path, key := rest[:i], rest[i+1:]
			v, ok := snap.fact(path, key)
			if !ok {
				return tok
			}
			return v
		case strings.HasPrefix(inner, "presence:"):
			path := strings.TrimPrefix(inner, "presence:")
			return string(snap.presence(path))
		}
		return tok
	})
}

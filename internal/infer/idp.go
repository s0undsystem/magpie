package infer

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed idp_patterns.json
var embeddedIdPPatterns []byte

// idpPattern is one entry in the identity-provider mapping file: Provider
// is reported when the issuer URL contains Match, case-insensitively. This
// is a data file specifically so new providers can be added without
// touching Go code — see CONTRIBUTING.md.
type idpPattern struct {
	Provider string `json:"provider"`
	Match    string `json:"match"`
}

var idpPatterns []idpPattern

func init() {
	if err := json.Unmarshal(embeddedIdPPatterns, &idpPatterns); err != nil {
		panic("infer: embedded idp_patterns.json is invalid: " + err.Error())
	}
}

// MatchIdentityProvider returns the known identity provider whose pattern
// matches issuer, checking patterns in file order (first match wins) so
// more specific patterns can be listed ahead of broader ones.
func MatchIdentityProvider(issuer string) (provider string, ok bool) {
	lower := strings.ToLower(issuer)
	for _, p := range idpPatterns {
		if strings.Contains(lower, strings.ToLower(p.Match)) {
			return p.Provider, true
		}
	}
	return "", false
}

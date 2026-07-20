package infer

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed idp_patterns.json
var embeddedIdPPatterns []byte

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

func MatchIdentityProvider(issuer string) (provider string, ok bool) {
	lower := strings.ToLower(issuer)
	for _, p := range idpPatterns {
		if strings.Contains(lower, strings.ToLower(p.Match)) {
			return p.Provider, true
		}
	}
	return "", false
}

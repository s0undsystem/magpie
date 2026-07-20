package infer

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed bugbounty_patterns.json
var embeddedBugBountyPatterns []byte

type bugBountyPattern struct {
	Platform string `json:"platform"`
	Match    string `json:"match"`
}

var bugBountyPatterns []bugBountyPattern

func init() {
	if err := json.Unmarshal(embeddedBugBountyPatterns, &bugBountyPatterns); err != nil {
		panic("infer: embedded bugbounty_patterns.json is invalid: " + err.Error())
	}
}

func MatchBugBountyPlatform(contactURL string) (platform string, ok bool) {
	lower := strings.ToLower(contactURL)
	for _, p := range bugBountyPatterns {
		if strings.Contains(lower, strings.ToLower(p.Match)) {
			return p.Platform, true
		}
	}
	return "", false
}

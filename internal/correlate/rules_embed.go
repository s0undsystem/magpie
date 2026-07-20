package correlate

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed rules.json
var embeddedRulesJSON []byte

func loadEmbeddedRules() ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(embeddedRulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("parsing embedded rules.json: %w", err)
	}
	return rules, nil
}

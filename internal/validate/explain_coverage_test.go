package validate

import (
	"testing"

	"github.com/s0undsystem/magpie/internal/explain"
)

func TestEveryValidatorFindingIDHasExplainDoc(t *testing.T) {
	want := []string{
		"SECTXT-001", "SECTXT-002", "SECTXT-003", "SECTXT-004", "SECTXT-005", "SECTXT-006",
		"SECTXT-007", "SECTXT-008", "SECTXT-009", "SECTXT-010", "SECTXT-011", "SECTXT-012",
		"OIDC-001", "OIDC-002", "OIDC-003", "OIDC-004", "OIDC-005",
		"MTASTS-001", "MTASTS-002", "MTASTS-003", "MTASTS-004", "MTASTS-005", "MTASTS-006", "MTASTS-007",
		"AAL-001", "AAL-002", "AAL-003", "AAL-004",
		"AASA-001", "AASA-002", "AASA-003",
		"CHPW-001",
	}
	for _, id := range want {
		if _, ok := explain.Lookup(id); !ok {
			t.Errorf("expected explain.Doc registered for %s", id)
		}
	}
}

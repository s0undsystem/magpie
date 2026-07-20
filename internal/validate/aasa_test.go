package validate

import (
	"testing"

	"github.com/harborproject/magpie/internal/scan"
)

func aasaResult(body, contentType string) scan.Result {
	return scan.Result{
		Presence:    scan.PresencePresent,
		URL:         "https://example.org/.well-known/apple-app-site-association",
		Body:        []byte(body),
		ContentType: contentType,
	}
}

func TestAASAValidator_Path(t *testing.T) {
	if got := (AASAValidator{}).Path(); got != "apple-app-site-association" {
		t.Errorf("Path() = %q", got)
	}
}

func TestAASAValidator_InvalidJSON(t *testing.T) {
	out := AASAValidator{}.Validate(Context{Result: aasaResult("not json", "application/json")})
	if !hasFinding(out.Findings, "AASA-001") {
		t.Error("expected AASA-001 (invalid JSON)")
	}
}

func TestAASAValidator_WrongContentType(t *testing.T) {
	body := `{"applinks":{"details":[{"appID":"ABCDE12345.org.example.app","paths":["*"]}]}}`
	out := AASAValidator{}.Validate(Context{Result: aasaResult(body, "text/plain")})
	if !hasFinding(out.Findings, "AASA-002") {
		t.Error("expected AASA-002 (wrong content type)")
	}
}

func TestAASAValidator_CorrectContentTypeNoFinding(t *testing.T) {
	body := `{"applinks":{"details":[{"appID":"ABCDE12345.org.example.app","paths":["*"]}]}}`
	out := AASAValidator{}.Validate(Context{Result: aasaResult(body, "application/json")})
	if hasFinding(out.Findings, "AASA-002") {
		t.Error("did not expect AASA-002 when content type is application/json")
	}
	if out.Facts["team_ids"] != "ABCDE12345" {
		t.Errorf("team_ids = %q", out.Facts["team_ids"])
	}
	if out.Facts["bundle_ids"] != "org.example.app" {
		t.Errorf("bundle_ids = %q", out.Facts["bundle_ids"])
	}
}

func TestAASAValidator_NoRecognizedSections(t *testing.T) {
	out := AASAValidator{}.Validate(Context{Result: aasaResult(`{}`, "application/json")})
	if !hasFinding(out.Findings, "AASA-003") {
		t.Error("expected AASA-003 (no applinks/webcredentials/appclips)")
	}
}

func TestAASAValidator_WebcredentialsExtracted(t *testing.T) {
	body := `{"webcredentials":{"apps":["ABCDE12345.org.example.app"]}}`
	out := AASAValidator{}.Validate(Context{Result: aasaResult(body, "application/json")})
	if hasFinding(out.Findings, "AASA-003") {
		t.Error("did not expect AASA-003 when webcredentials is present")
	}
	if out.Facts["bundle_ids"] != "org.example.app" {
		t.Errorf("bundle_ids = %q", out.Facts["bundle_ids"])
	}
}

func TestAASAValidator_NotPresentSkips(t *testing.T) {
	out := AASAValidator{}.Validate(Context{Result: scan.Result{Presence: scan.PresenceAbsent}})
	if len(out.Findings) != 0 {
		t.Error("expected no findings when not present")
	}
}

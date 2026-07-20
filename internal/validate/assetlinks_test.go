package validate

import (
	"testing"

	"github.com/harborproject/magpie/internal/scan"
)

func assetlinksResult(body string) scan.Result {
	return scan.Result{Presence: scan.PresencePresent, URL: "https://example.org/.well-known/assetlinks.json", Body: []byte(body)}
}

func TestAssetLinksValidator_Path(t *testing.T) {
	if got := (AssetLinksValidator{}).Path(); got != "assetlinks.json" {
		t.Errorf("Path() = %q", got)
	}
}

func TestAssetLinksValidator_InvalidJSON(t *testing.T) {
	out := AssetLinksValidator{}.Validate(Context{Result: assetlinksResult(`{"not":"an array"}`)})
	if !hasFinding(out.Findings, "AAL-001") {
		t.Error("expected AAL-001 (not a JSON array)")
	}
}

func TestAssetLinksValidator_ValidStatement(t *testing.T) {
	body := `[{
		"relation": ["delegate_permission/common.handle_all_urls"],
		"target": {
			"namespace": "android_app",
			"package_name": "org.example.app",
			"sha256_cert_fingerprints": ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"]
		}
	}]`
	out := AssetLinksValidator{}.Validate(Context{Result: assetlinksResult(body)})
	if len(out.Findings) != 0 {
		t.Errorf("expected no findings for a valid statement, got %+v", out.Findings)
	}
	if out.Facts["package_names"] != "org.example.app" {
		t.Errorf("package_names = %q", out.Facts["package_names"])
	}
}

func TestAssetLinksValidator_MissingRelationOrTarget(t *testing.T) {
	body := `[{"relation": [], "target": {"namespace":"android_app"}}]`
	out := AssetLinksValidator{}.Validate(Context{Result: assetlinksResult(body)})
	if !hasFinding(out.Findings, "AAL-002") {
		t.Error("expected AAL-002 (missing relation/package_name)")
	}
}

func TestAssetLinksValidator_BadRelationFormat(t *testing.T) {
	body := `[{
		"relation": ["not_a_valid_relation"],
		"target": {"namespace":"android_app","package_name":"org.example.app"}
	}]`
	out := AssetLinksValidator{}.Validate(Context{Result: assetlinksResult(body)})
	if !hasFinding(out.Findings, "AAL-003") {
		t.Error("expected AAL-003 (bad relation format)")
	}
}

func TestAssetLinksValidator_BadFingerprint(t *testing.T) {
	body := `[{
		"relation": ["delegate_permission/common.handle_all_urls"],
		"target": {"namespace":"android_app","package_name":"org.example.app","sha256_cert_fingerprints":["not-a-fingerprint"]}
	}]`
	out := AssetLinksValidator{}.Validate(Context{Result: assetlinksResult(body)})
	if !hasFinding(out.Findings, "AAL-004") {
		t.Error("expected AAL-004 (bad fingerprint format)")
	}
}

func TestAssetLinksValidator_NotPresentSkips(t *testing.T) {
	out := AssetLinksValidator{}.Validate(Context{Result: scan.Result{Presence: scan.PresenceSoft404}})
	if len(out.Findings) != 0 {
		t.Error("expected no findings when not present")
	}
}

package validate

import (
	"testing"

	"github.com/s0undsystem/magpie/internal/scan"
)

func oidcResult(body string) scan.Result {
	return scan.Result{Presence: scan.PresencePresent, URL: "https://example.org/.well-known/openid-configuration", Body: []byte(body)}
}

func TestOpenIDConfigValidator_Path(t *testing.T) {
	if got := (OpenIDConfigValidator{}).Path(); got != "openid-configuration" {
		t.Errorf("Path() = %q", got)
	}
}

func TestOpenIDConfigValidator_InvalidJSON(t *testing.T) {
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult("not json")})
	if !hasFinding(out.Findings, "OIDC-001") {
		t.Error("expected OIDC-001 (invalid JSON)")
	}
}

func TestOpenIDConfigValidator_NoSigningAlgs(t *testing.T) {
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(`{"issuer":"https://example.org"}`)})
	if !hasFinding(out.Findings, "OIDC-002") {
		t.Error("expected OIDC-002 (no id_token_signing_alg_values_supported)")
	}
	if out.Facts["issuer"] != "https://example.org" {
		t.Errorf("issuer fact = %q", out.Facts["issuer"])
	}
}

func TestOpenIDConfigValidator_ImplicitGrant(t *testing.T) {
	body := `{
		"issuer":"https://example.org",
		"id_token_signing_alg_values_supported":["RS256"],
		"response_types_supported":["code","token"],
		"code_challenge_methods_supported":["S256"]
	}`
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(body)})
	if !hasFinding(out.Findings, "OIDC-003") {
		t.Error("expected OIDC-003 (implicit grant)")
	}
}

func TestOpenIDConfigValidator_MissingS256(t *testing.T) {
	body := `{
		"issuer":"https://example.org",
		"id_token_signing_alg_values_supported":["RS256"],
		"response_types_supported":["code"],
		"code_challenge_methods_supported":["plain"]
	}`
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(body)})
	if !hasFinding(out.Findings, "OIDC-004") {
		t.Error("expected OIDC-004 (missing S256)")
	}
}

func TestOpenIDConfigValidator_SoleClientSecretBasic(t *testing.T) {
	body := `{
		"issuer":"https://example.org",
		"id_token_signing_alg_values_supported":["RS256"],
		"response_types_supported":["code"],
		"code_challenge_methods_supported":["S256"],
		"token_endpoint_auth_methods_supported":["client_secret_basic"]
	}`
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(body)})
	if !hasFinding(out.Findings, "OIDC-005") {
		t.Error("expected OIDC-005 (sole client_secret_basic)")
	}
}

func TestOpenIDConfigValidator_CleanConfigNoFindings(t *testing.T) {
	body := `{
		"issuer":"https://example.org",
		"id_token_signing_alg_values_supported":["RS256"],
		"response_types_supported":["code"],
		"code_challenge_methods_supported":["S256"],
		"token_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"]
	}`
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(body)})
	if len(out.Findings) != 0 {
		t.Errorf("expected no findings for a clean config, got %+v", out.Findings)
	}
}

func TestOpenIDConfigValidator_RequestURIFacts(t *testing.T) {
	body := `{
		"issuer":"https://example.org",
		"id_token_signing_alg_values_supported":["RS256"],
		"response_types_supported":["code"],
		"code_challenge_methods_supported":["S256"],
		"request_uri_parameter_supported": true,
		"require_request_uri_registration": false
	}`
	out := OpenIDConfigValidator{}.Validate(Context{Result: oidcResult(body)})
	if out.Facts["request_uri_parameter_supported"] != "true" {
		t.Errorf("request_uri_parameter_supported = %q", out.Facts["request_uri_parameter_supported"])
	}
	if out.Facts["require_request_uri_registration"] != "false" {
		t.Errorf("require_request_uri_registration = %q", out.Facts["require_request_uri_registration"])
	}
}

func TestOpenIDConfigValidator_NotPresentSkips(t *testing.T) {
	out := OpenIDConfigValidator{}.Validate(Context{Result: scan.Result{Presence: scan.PresenceAbsent}})
	if len(out.Findings) != 0 {
		t.Error("expected no findings when not present")
	}
}

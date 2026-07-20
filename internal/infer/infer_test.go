package infer

import (
	"reflect"
	"testing"

	"github.com/harborproject/magpie/internal/correlate"
	"github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

func snap(docs map[string]correlate.DocFacts) correlate.Snapshot {
	return correlate.Snapshot{Host: "example.org", Docs: docs}
}

func doc(presence scan.Presence, facts map[string]string) correlate.DocFacts {
	return correlate.DocFacts{Presence: presence, Facts: validate.Facts(facts)}
}

func TestMatchIdentityProviderKnownProviders(t *testing.T) {
	cases := map[string]string{
		"https://example.okta.com":                    "Okta",
		"https://login.microsoftonline.com/tenant/v2": "Microsoft Entra ID",
		"https://example.auth0.com/":                  "Auth0",
		"https://auth.pingone.com":                    "Ping Identity",
		"https://accounts.google.com":                 "Google",
		"https://cognito-idp.us-east-1.amazonaws.com": "AWS Cognito",
		"https://idp.example.org/realms/master":       "Keycloak",
	}
	for issuer, want := range cases {
		got, ok := MatchIdentityProvider(issuer)
		if !ok {
			t.Errorf("MatchIdentityProvider(%q): no match, want %q", issuer, want)
			continue
		}
		if got != want {
			t.Errorf("MatchIdentityProvider(%q) = %q, want %q", issuer, got, want)
		}
	}
}

func TestMatchIdentityProviderUnknown(t *testing.T) {
	if _, ok := MatchIdentityProvider("https://idp.someselfhostedcompany.internal"); ok {
		t.Error("expected no match for an unrecognized issuer")
	}
}

func TestInferIdentityProvider(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"issuer": "https://example.okta.com"}),
	})
	res := Infer(s)
	if res.IdentityProvider == nil {
		t.Fatal("expected an identity provider inference")
	}
	if res.IdentityProvider.Provider != "Okta" || res.IdentityProvider.Issuer != "https://example.okta.com" {
		t.Errorf("IdentityProvider = %+v", res.IdentityProvider)
	}
}

func TestInferIdentityProviderAbsentWhenNotPresent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"openid-configuration": doc(scan.PresenceAbsent, nil),
	})
	res := Infer(s)
	if res.IdentityProvider != nil {
		t.Errorf("expected nil IdentityProvider, got %+v", res.IdentityProvider)
	}
}

func TestInferIdentityProviderNoMatch(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"issuer": "https://idp.selfhosted.internal"}),
	})
	res := Infer(s)
	if res.IdentityProvider != nil {
		t.Errorf("expected nil IdentityProvider for an unrecognized issuer, got %+v", res.IdentityProvider)
	}
}

func TestInferMobileAppsBothPlatforms(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"assetlinks.json":            doc(scan.PresencePresent, map[string]string{"package_names": "org.example.app,org.example.app2"}),
		"apple-app-site-association": doc(scan.PresencePresent, map[string]string{"bundle_ids": "org.example.app"}),
	})
	res := Infer(s)
	if len(res.MobileApps) != 2 {
		t.Fatalf("expected 2 mobile app entries, got %d: %+v", len(res.MobileApps), res.MobileApps)
	}
	var platforms []string
	for _, a := range res.MobileApps {
		platforms = append(platforms, a.Platform)
	}
	if !reflect.DeepEqual(platforms, []string{"android", "ios"}) {
		t.Errorf("platforms = %v, want [android ios]", platforms)
	}
	if !reflect.DeepEqual(res.MobileApps[0].Identifiers, []string{"org.example.app", "org.example.app2"}) {
		t.Errorf("android identifiers = %v", res.MobileApps[0].Identifiers)
	}
}

func TestInferMobileAppsNoneWhenAbsent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"assetlinks.json":            doc(scan.PresenceAbsent, nil),
		"apple-app-site-association": doc(scan.PresenceSoft404, nil),
	})
	res := Infer(s)
	if len(res.MobileApps) != 0 {
		t.Errorf("expected no mobile apps, got %+v", res.MobileApps)
	}
}

func TestInferMailSecurityConfiguredAndActivated(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{"mode": "enforce", "mta_sts_dns_txt_present": "true"}),
	})
	res := Infer(s)
	want := &MailSecurity{Configured: true, Mode: "enforce", DNSActivated: true}
	if !reflect.DeepEqual(res.MailSecurity, want) {
		t.Errorf("MailSecurity = %+v, want %+v", res.MailSecurity, want)
	}
}

func TestInferMailSecurityNotConfigured(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"mta-sts.txt": doc(scan.PresenceAbsent, nil),
	})
	res := Infer(s)
	want := &MailSecurity{Configured: false}
	if !reflect.DeepEqual(res.MailSecurity, want) {
		t.Errorf("MailSecurity = %+v, want %+v", res.MailSecurity, want)
	}
}

func TestInferMatrixFromServer(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"matrix/server": doc(scan.PresencePresent, map[string]string{"server_name": "matrix.example.org:8448"}),
	})
	res := Infer(s)
	want := &MatrixHomeserver{Source: "matrix/server", Address: "matrix.example.org:8448"}
	if !reflect.DeepEqual(res.Matrix, want) {
		t.Errorf("Matrix = %+v, want %+v", res.Matrix, want)
	}
}

func TestInferMatrixFallsBackToClient(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"matrix/client": doc(scan.PresencePresent, map[string]string{"homeserver_base_url": "https://matrix.example.org"}),
	})
	res := Infer(s)
	want := &MatrixHomeserver{Source: "matrix/client", Address: "https://matrix.example.org"}
	if !reflect.DeepEqual(res.Matrix, want) {
		t.Errorf("Matrix = %+v, want %+v", res.Matrix, want)
	}
}

func TestInferMatrixServerTakesPrecedenceOverClient(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"matrix/server": doc(scan.PresencePresent, map[string]string{"server_name": "matrix.example.org:8448"}),
		"matrix/client": doc(scan.PresencePresent, map[string]string{"homeserver_base_url": "https://matrix.example.org"}),
	})
	res := Infer(s)
	if res.Matrix.Source != "matrix/server" {
		t.Errorf("Matrix.Source = %q, want matrix/server", res.Matrix.Source)
	}
}

func TestInferMatrixNilWhenAbsent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{})
	res := Infer(s)
	if res.Matrix != nil {
		t.Errorf("expected nil Matrix, got %+v", res.Matrix)
	}
}

func TestInferACMEPresent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"acme-challenge": doc(scan.PresencePresent, nil),
	})
	res := Infer(s)
	if res.ACME == nil || !res.ACME.Present {
		t.Errorf("ACME = %+v, want Present=true", res.ACME)
	}
}

func TestInferACMEAbsent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"acme-challenge": doc(scan.PresenceAbsent, nil),
	})
	res := Infer(s)
	if res.ACME == nil || res.ACME.Present {
		t.Errorf("ACME = %+v, want Present=false", res.ACME)
	}
}

func TestInferACMENilDocStillReturnsNotPresent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{})
	res := Infer(s)
	if res.ACME == nil || res.ACME.Present {
		t.Errorf("ACME = %+v, want non-nil with Present=false", res.ACME)
	}
}

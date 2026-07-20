package validate

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/s0undsystem/magpie/internal/domainutil"
	"github.com/s0undsystem/magpie/internal/explain"
	"github.com/s0undsystem/magpie/internal/finding"
	"github.com/s0undsystem/magpie/internal/scan"
)

func init() {
	Register(OpenIDConfigValidator{})

	explain.Register(explain.Doc{
		ID: "OIDC-001", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryAuth,
		Message: "openid-configuration did not parse as valid JSON.", SpecRef: "OpenID Connect Discovery 1.0 §3",
		Explanation: "OpenID Connect Discovery requires this document to be a valid JSON object; if it isn't, no relying party can actually use it to configure itself. Remediation: fix whatever is generating this file so it emits valid JSON.",
	})
	explain.Register(explain.Doc{
		ID: "OIDC-002", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryAuth,
		Message: "openid-configuration does not advertise any id_token_signing_alg_values_supported.", SpecRef: "OpenID Connect Discovery 1.0 §3",
		Explanation: "Without at least one advertised signing algorithm, relying parties have no way to know how to verify ID tokens issued by this provider, which breaks OIDC's core trust model. Remediation: publish id_token_signing_alg_values_supported with the algorithm(s) actually used, e.g. [\"RS256\"].",
	})
	explain.Register(explain.Doc{
		ID: "OIDC-003", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryAuth,
		Message: "openid-configuration advertises the implicit grant, which returns tokens directly in the redirect URI.", SpecRef: "OAuth 2.0 Security Best Current Practice §2.1.2",
		Explanation: "The implicit grant returns access/ID tokens in the URL fragment, which can leak via browser history, referrer headers, and server logs, and offers no client authentication. Current OAuth 2.0 best practice recommends against it in favor of authorization code + PKCE. Remediation: remove \"token\" and \"id_token token\" from response_types_supported and migrate clients to the authorization code flow with PKCE.",
	})
	explain.Register(explain.Doc{
		ID: "OIDC-004", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryAuth,
		Message: "openid-configuration does not advertise PKCE with the S256 code_challenge_method.", SpecRef: "RFC 7636",
		Explanation: "PKCE (RFC 7636) protects the authorization code flow from interception, and is now considered mandatory-in-practice for public clients (mobile/SPA). S256 is the only code_challenge_method current guidance recommends; \"plain\" alone provides little protection. Remediation: advertise code_challenge_methods_supported including \"S256\".",
	})
	explain.Register(explain.Doc{
		ID: "OIDC-005", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain, Category: finding.CategoryAuth,
		Message: "openid-configuration supports only client_secret_basic for token endpoint authentication.", SpecRef: "RFC 8414 §2",
		Explanation: "client_secret_basic sends a shared secret over TLS on every token request; it works, but stronger options exist (private_key_jwt, mTLS) for clients that can use them. This is informational, not a defect on its own.",
	})
}

type OpenIDConfigValidator struct{}

func (OpenIDConfigValidator) Path() string { return "openid-configuration" }

type openIDDoc struct {
	Issuer                            string   `json:"issuer"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	RequestURIParameterSupported      *bool    `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration     *bool    `json:"require_request_uri_registration"`
}

func (OpenIDConfigValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result
	if r.Presence != scan.PresencePresent {
		return out
	}

	var doc openIDDoc
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "OIDC-001", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryAuth,
			Message:  "openid-configuration did not parse as valid JSON.",
			Evidence: finalURL(r), SpecRef: "OpenID Connect Discovery 1.0 §3",
		})
		return out
	}

	if doc.Issuer != "" {
		out.Facts["issuer"] = doc.Issuer
	}
	if doc.JWKSURI != "" {
		out.Facts["jwks_uri"] = doc.JWKSURI
	}
	if doc.TokenEndpoint != "" {
		out.Facts["token_endpoint"] = doc.TokenEndpoint
	}
	if doc.AuthorizationEndpoint != "" {
		out.Facts["authorization_endpoint"] = doc.AuthorizationEndpoint
	}

	if len(doc.IDTokenSigningAlgValuesSupported) == 0 {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "OIDC-002", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryAuth,
			Message:  "openid-configuration does not advertise any id_token_signing_alg_values_supported.",
			Evidence: finalURL(r), SpecRef: "OpenID Connect Discovery 1.0 §3",
		})
	} else {
		out.Facts["id_token_signing_alg_values_supported"] = strings.Join(doc.IDTokenSigningAlgValuesSupported, ",")
	}

	if hasAnyFold(doc.ResponseTypesSupported, "token", "id_token token") {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "OIDC-003", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryAuth,
			Message:  "openid-configuration advertises the implicit grant, which returns tokens directly in the redirect URI.",
			Evidence: strings.Join(doc.ResponseTypesSupported, ", "), SpecRef: "OAuth 2.0 Security Best Current Practice §2.1.2",
		})
	}
	if len(doc.ResponseTypesSupported) > 0 {
		out.Facts["response_types_supported"] = strings.Join(doc.ResponseTypesSupported, ",")
	}

	if !containsFold(doc.CodeChallengeMethodsSupported, "S256") {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "OIDC-004", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryAuth,
			Message:  "openid-configuration does not advertise PKCE with the S256 code_challenge_method.",
			Evidence: strings.Join(doc.CodeChallengeMethodsSupported, ", "), SpecRef: "RFC 7636",
		})
	}
	if len(doc.CodeChallengeMethodsSupported) > 0 {
		out.Facts["code_challenge_methods_supported"] = strings.Join(doc.CodeChallengeMethodsSupported, ",")
	}

	if len(doc.TokenEndpointAuthMethodsSupported) == 1 && strings.EqualFold(doc.TokenEndpointAuthMethodsSupported[0], "client_secret_basic") {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "OIDC-005", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryAuth,
			Message:  "openid-configuration supports only client_secret_basic for token endpoint authentication.",
			Evidence: "token_endpoint_auth_methods_supported: client_secret_basic", SpecRef: "RFC 8414 §2",
		})
	}
	if len(doc.TokenEndpointAuthMethodsSupported) > 0 {
		out.Facts["token_endpoint_auth_methods_supported"] = strings.Join(doc.TokenEndpointAuthMethodsSupported, ",")
	}

	if doc.RequestURIParameterSupported != nil && *doc.RequestURIParameterSupported {
		out.Facts["request_uri_parameter_supported"] = "true"
		required := doc.RequireRequestURIRegistration != nil && *doc.RequireRequestURIRegistration
		out.Facts["require_request_uri_registration"] = strconv.FormatBool(required)
	}

	addOIDCCrossCheckFacts(doc, ctx, &out)

	return out
}

func addOIDCCrossCheckFacts(doc openIDDoc, ctx Context, out *Output) {
	if doc.Issuer != "" {
		if u, err := url.Parse(doc.Issuer); err == nil && u.Hostname() != "" {
			out.Facts["issuer_matches_origin"] = strconv.FormatBool(domainutil.SameRegistrable(u.Hostname(), ctx.Host))
		}
	}
	if doc.JWKSURI != "" && doc.Issuer != "" {
		ju, jerr := url.Parse(doc.JWKSURI)
		iu, ierr := url.Parse(doc.Issuer)
		if jerr == nil && ierr == nil && ju.Hostname() != "" && iu.Hostname() != "" {
			out.Facts["jwks_uri_offsite"] = strconv.FormatBool(!domainutil.SameRegistrable(ju.Hostname(), iu.Hostname()))
		}
	}

	var endpoints []string
	for _, e := range []string{doc.Issuer, doc.JWKSURI, doc.TokenEndpoint, doc.AuthorizationEndpoint} {
		if e != "" {
			endpoints = append(endpoints, e)
		}
	}
	if len(endpoints) > 0 {
		out.Facts["endpoint_urls"] = strings.Join(endpoints, ",")
	}
}

func hasAnyFold(list []string, targets ...string) bool {
	for _, item := range list {
		for _, t := range targets {
			if strings.EqualFold(item, t) {
				return true
			}
		}
	}
	return false
}

func containsFold(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

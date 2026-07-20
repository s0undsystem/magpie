package validate

import (
	"encoding/json"
	"strings"

	"github.com/harborproject/magpie/internal/scan"
)

func init() { Register(OAuthAuthServerValidator{}) }

// OAuthAuthServerValidator extracts facts from
// /.well-known/oauth-authorization-server (RFC 8414). It is not one of
// magpie's required validators — no dedicated findings are defined for it —
// but the correlation engine cross-checks its issuer and endpoint values
// against openid-configuration (CORR-019, CORR-020), so magpie still parses
// it and exposes the same fact shape as OpenIDConfigValidator.
type OAuthAuthServerValidator struct{}

func (OAuthAuthServerValidator) Path() string { return "oauth-authorization-server" }

func (OAuthAuthServerValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result
	if r.Presence != scan.PresencePresent {
		return out
	}

	var doc openIDDoc
	if err := json.Unmarshal(r.Body, &doc); err != nil {
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
	if len(doc.CodeChallengeMethodsSupported) > 0 {
		out.Facts["code_challenge_methods_supported"] = strings.Join(doc.CodeChallengeMethodsSupported, ",")
	}

	addOIDCCrossCheckFacts(doc, ctx, &out)

	return out
}

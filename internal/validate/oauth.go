package validate

import (
	"encoding/json"
	"strings"

	"github.com/harborproject/magpie/internal/scan"
)

func init() { Register(OAuthAuthServerValidator{}) }

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

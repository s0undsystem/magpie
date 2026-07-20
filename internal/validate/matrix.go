package validate

import (
	"encoding/json"

	"github.com/s0undsystem/magpie/internal/scan"
)

func init() {
	Register(MatrixServerValidator{})
	Register(MatrixClientValidator{})
}

type MatrixServerValidator struct{}

func (MatrixServerValidator) Path() string { return "matrix/server" }

type matrixServerDoc struct {
	Server string `json:"m.server"`
}

func (MatrixServerValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	if ctx.Result.Presence != scan.PresencePresent {
		return out
	}
	var doc matrixServerDoc
	if err := json.Unmarshal(ctx.Result.Body, &doc); err != nil || doc.Server == "" {
		return out
	}
	out.Facts["server_name"] = doc.Server
	return out
}

type MatrixClientValidator struct{}

func (MatrixClientValidator) Path() string { return "matrix/client" }

type matrixHomeserverRef struct {
	BaseURL string `json:"base_url"`
}

type matrixClientDoc struct {
	Homeserver matrixHomeserverRef `json:"m.homeserver"`
}

func (MatrixClientValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	if ctx.Result.Presence != scan.PresencePresent {
		return out
	}
	var doc matrixClientDoc
	if err := json.Unmarshal(ctx.Result.Body, &doc); err != nil || doc.Homeserver.BaseURL == "" {
		return out
	}
	out.Facts["homeserver_base_url"] = doc.Homeserver.BaseURL
	return out
}

package validate

import (
	"testing"

	"github.com/s0undsystem/magpie/internal/scan"
)

func TestMatrixServerValidator(t *testing.T) {
	out := MatrixServerValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		Body:     []byte(`{"m.server":"matrix.example.org:8448"}`),
	}})
	if out.Facts["server_name"] != "matrix.example.org:8448" {
		t.Errorf("server_name = %q", out.Facts["server_name"])
	}
}

func TestMatrixServerValidator_NotPresentSkips(t *testing.T) {
	out := MatrixServerValidator{}.Validate(Context{Result: scan.Result{Presence: scan.PresenceAbsent}})
	if len(out.Facts) != 0 {
		t.Errorf("expected no facts, got %+v", out.Facts)
	}
}

func TestMatrixClientValidator(t *testing.T) {
	out := MatrixClientValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		Body:     []byte(`{"m.homeserver":{"base_url":"https://matrix.example.org"}}`),
	}})
	if out.Facts["homeserver_base_url"] != "https://matrix.example.org" {
		t.Errorf("homeserver_base_url = %q", out.Facts["homeserver_base_url"])
	}
}

func TestMatrixClientValidator_InvalidJSON(t *testing.T) {
	out := MatrixClientValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		Body:     []byte("not json"),
	}})
	if len(out.Facts) != 0 {
		t.Errorf("expected no facts for invalid JSON, got %+v", out.Facts)
	}
}

func TestMatrixValidatorsRegistered(t *testing.T) {
	if _, ok := Lookup("matrix/server"); !ok {
		t.Error("expected matrix/server to be registered")
	}
	if _, ok := Lookup("matrix/client"); !ok {
		t.Error("expected matrix/client to be registered")
	}
}

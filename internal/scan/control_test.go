package scan

import (
	"math/rand"
	"testing"
)

func TestControlTokenLengthAndCharset(t *testing.T) {
	tok := ControlToken(rand.New(rand.NewSource(1)))
	if len(tok) != 32 {
		t.Fatalf("len(token) = %d, want 32", len(tok))
	}
	for _, r := range tok {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			t.Fatalf("token contains unexpected character %q", r)
		}
	}
}

func TestResemblesControlIdenticalBody(t *testing.T) {
	ctrl := Control{StatusCode: 200, ContentType: "text/html", BodyHash: hashBody([]byte("not found")), BodyLength: len("not found")}
	raw := &rawResponse{StatusCode: 200, ContentType: "text/html", Body: []byte("not found")}
	if !resemblesControl(raw, ctrl) {
		t.Error("expected identical body to resemble control")
	}
}

func TestResemblesControlDifferentStatus(t *testing.T) {
	ctrl := Control{StatusCode: 404, ContentType: "text/plain", BodyHash: hashBody([]byte("x")), BodyLength: 1}
	raw := &rawResponse{StatusCode: 200, ContentType: "text/plain", Body: []byte("x")}
	if resemblesControl(raw, ctrl) {
		t.Error("different status codes must never resemble the control")
	}
}

func TestResemblesControlLengthTolerance(t *testing.T) {
	controlBody := []byte("Sorry, the page you requested (RANDOMTOKEN) could not be found on this server.")
	ctrl := newControl(&rawResponse{StatusCode: 200, ContentType: "text/html", Body: controlBody})

	echoedBody := []byte("Sorry, the page you requested (openid-configuration) could not be found on this server.")
	raw := &rawResponse{StatusCode: 200, ContentType: "text/html", Body: echoedBody}
	if !resemblesControl(raw, ctrl) {
		t.Error("expected a template that echoes the request path to still resemble the control within tolerance")
	}
}

func TestResemblesControlGenuinelyDifferentContent(t *testing.T) {
	ctrl := newControl(&rawResponse{StatusCode: 200, ContentType: "text/html", Body: []byte("short generic error page")})
	raw := &rawResponse{
		StatusCode:  200,
		ContentType: "text/html",
		Body:        []byte("This is a completely different, much longer page containing real security.txt-style content that should not be mistaken for the generic error template at all."),
	}
	if resemblesControl(raw, ctrl) {
		t.Error("substantially different content must not resemble the control")
	}
}

func TestBaseContentTypeStripsParameters(t *testing.T) {
	if got := baseContentType("text/plain; charset=utf-8"); got != "text/plain" {
		t.Errorf("baseContentType() = %q, want %q", got, "text/plain")
	}
}

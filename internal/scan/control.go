package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strings"
	"time"
)

const controlTokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// ControlToken generates a random 32-character token used to probe a
// well-known path that cannot legitimately be documented, establishing a
// soft-404 baseline before the real scan. Pass nil to seed from the clock;
// tests can pass a deterministic *rand.Rand.
func ControlToken(rng *rand.Rand) string {
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	b := make([]byte, 32)
	for i := range b {
		b[i] = controlTokenCharset[rng.Intn(len(controlTokenCharset))]
	}
	return string(b)
}

// Control is the baseline response captured by probing a well-known path
// that does not exist in the registry, used to detect hosts that return
// HTTP 200 with a generic error/landing page for any path.
type Control struct {
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
	BodyLength  int    `json:"body_length"`
	BodyHash    string `json:"body_hash"`
}

// normalizeBody strips leading/trailing whitespace and normalizes line
// endings so that trivial whitespace differences don't defeat hash
// comparison.
func normalizeBody(body []byte) []byte {
	s := strings.ReplaceAll(string(body), "\r\n", "\n")
	return []byte(strings.TrimSpace(s))
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(normalizeBody(body))
	return hex.EncodeToString(sum[:])
}

func newControl(raw *rawResponse) Control {
	return Control{
		StatusCode:  raw.StatusCode,
		ContentType: raw.ContentType,
		BodyLength:  len(normalizeBody(raw.Body)),
		BodyHash:    hashBody(raw.Body),
	}
}

// resemblesControl reports whether raw looks like the soft-404 control
// response: the same status and content type, and either an identical body
// hash or a body length within a small tolerance. The tolerance accounts for
// error templates that echo the requested path name back into otherwise
// identical boilerplate, which would otherwise defeat exact hash matching.
func resemblesControl(raw *rawResponse, ctrl Control) bool {
	if raw.StatusCode != ctrl.StatusCode {
		return false
	}
	if !strings.EqualFold(baseContentType(raw.ContentType), baseContentType(ctrl.ContentType)) {
		return false
	}
	if hashBody(raw.Body) == ctrl.BodyHash {
		return true
	}
	length := len(normalizeBody(raw.Body))
	tolerance := ctrl.BodyLength / 20
	if tolerance < 32 {
		tolerance = 32
	}
	delta := length - ctrl.BodyLength
	if delta < 0 {
		delta = -delta
	}
	return delta <= tolerance
}

func baseContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

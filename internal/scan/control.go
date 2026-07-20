package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strings"
	"time"
)

const controlTokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

type Control struct {
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
	BodyLength  int    `json:"body_length"`
	BodyHash    string `json:"body_hash"`
}

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

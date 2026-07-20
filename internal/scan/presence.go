package scan

// Presence is magpie's determination of whether a documented well-known
// path is genuinely present on a host, derived from more than a bare status
// code check.
type Presence string

const (
	// PresencePresent means the path returned 200, differed meaningfully
	// from the soft-404 control response, and (when the spec constrains the
	// content kind) parsed as expected.
	PresencePresent Presence = "present"
	// PresenceAbsent means the path returned a non-200 status.
	PresenceAbsent Presence = "absent"
	// PresenceSoft404 means the path returned 200 but the response is
	// indistinguishable from (or a kind-mismatched variant of) the host's
	// generic error page.
	PresenceSoft404 Presence = "soft404"
	// PresenceError means the request itself failed (network error,
	// timeout, too many redirects).
	PresenceError Presence = "error"
	// PresenceRedirectedOffsite means resolving the path redirected to a
	// different host than the one requested.
	PresenceRedirectedOffsite Presence = "redirected-offsite"
)

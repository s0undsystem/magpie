package scan

type Presence string

const (
	PresencePresent Presence = "present"

	PresenceAbsent Presence = "absent"

	PresenceSoft404 Presence = "soft404"

	PresenceError Presence = "error"

	PresenceRedirectedOffsite Presence = "redirected-offsite"
)

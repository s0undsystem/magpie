// Package version holds the magpie build version, injected via ldflags.
package version

// Version is overridden at build time with -ldflags "-X ...version.Version=vX.Y.Z".
var Version = "dev"

// UserAgent is the default User-Agent header magpie sends on every request.
func UserAgent(repoURL string) string {
	if repoURL == "" {
		repoURL = "https://github.com/harborproject/magpie"
	}
	return "magpie/" + Version + " (+" + repoURL + ")"
}

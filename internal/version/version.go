package version

var Version = "dev"

func UserAgent(repoURL string) string {
	if repoURL == "" {
		repoURL = "https://github.com/s0undsystem/magpie"
	}
	return "magpie/" + Version + " (+" + repoURL + ")"
}

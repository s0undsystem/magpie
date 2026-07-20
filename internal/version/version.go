package version

var Version = "dev"

func UserAgent(repoURL string) string {
	if repoURL == "" {
		repoURL = "https://github.com/harborproject/magpie"
	}
	return "magpie/" + Version + " (+" + repoURL + ")"
}

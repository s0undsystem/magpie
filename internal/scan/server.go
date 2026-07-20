package scan

import "net/http"

// DetectServer derives a short, best-effort CDN or server label from
// response headers. It only reads headers already returned by the single GET
// magpie made for the path; it performs no additional probing.
func DetectServer(h http.Header) string {
	if h == nil {
		return ""
	}
	switch {
	case h.Get("CF-Ray") != "":
		return "Cloudflare"
	case h.Get("X-Amz-Cf-Id") != "":
		return "Amazon CloudFront"
	case h.Get("X-Fastly-Request-Id") != "":
		return "Fastly"
	case h.Get("X-Akamai-Transformed") != "":
		return "Akamai"
	case h.Get("X-Vercel-Id") != "":
		return "Vercel"
	case h.Get("X-GitHub-Request-Id") != "":
		return "GitHub Pages"
	}
	if s := h.Get("Server"); s != "" {
		return s
	}
	return ""
}

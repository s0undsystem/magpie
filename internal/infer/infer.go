package infer

import (
	"strings"

	"github.com/s0undsystem/magpie/internal/correlate"
	"github.com/s0undsystem/magpie/internal/scan"
)

type IdentityProvider struct {
	Provider string
	Issuer   string
}

type MobileApp struct {
	Platform    string
	Identifiers []string
}

type MailSecurity struct {
	Configured   bool
	Mode         string
	DNSActivated bool
}

type MatrixHomeserver struct {
	Source  string
	Address string
}

type ACME struct {
	Present bool
}

type BugBountyProgram struct {
	Platform string
	URL      string
}

type Result struct {
	IdentityProvider *IdentityProvider
	MobileApps       []MobileApp
	MailSecurity     *MailSecurity
	Matrix           *MatrixHomeserver
	ACME             *ACME
	BugBountyProgram *BugBountyProgram
}

func Infer(snap correlate.Snapshot) Result {
	var res Result

	res.IdentityProvider = inferIdentityProvider(snap)
	res.MobileApps = inferMobileApps(snap)
	res.MailSecurity = inferMailSecurity(snap)
	res.Matrix = inferMatrix(snap)
	res.ACME = inferACME(snap)
	res.BugBountyProgram = inferBugBountyProgram(snap)

	return res
}

func inferIdentityProvider(snap correlate.Snapshot) *IdentityProvider {
	d, ok := snap.Docs["openid-configuration"]
	if !ok || d.Presence != scan.PresencePresent {
		return nil
	}
	issuer, ok := d.Facts["issuer"]
	if !ok || issuer == "" {
		return nil
	}
	provider, matched := MatchIdentityProvider(issuer)
	if !matched {
		return nil
	}
	return &IdentityProvider{Provider: provider, Issuer: issuer}
}

func inferMobileApps(snap correlate.Snapshot) []MobileApp {
	var apps []MobileApp
	if d, ok := snap.Docs["assetlinks.json"]; ok && d.Presence == scan.PresencePresent {
		if pkgs, ok := d.Facts["package_names"]; ok && pkgs != "" {
			apps = append(apps, MobileApp{Platform: "android", Identifiers: strings.Split(pkgs, ",")})
		}
	}
	if d, ok := snap.Docs["apple-app-site-association"]; ok && d.Presence == scan.PresencePresent {
		if ids, ok := d.Facts["bundle_ids"]; ok && ids != "" {
			apps = append(apps, MobileApp{Platform: "ios", Identifiers: strings.Split(ids, ",")})
		}
	}
	return apps
}

func inferMailSecurity(snap correlate.Snapshot) *MailSecurity {
	d, ok := snap.Docs["mta-sts.txt"]
	if !ok || d.Presence != scan.PresencePresent {
		return &MailSecurity{Configured: false}
	}
	return &MailSecurity{
		Configured:   true,
		Mode:         d.Facts["mode"],
		DNSActivated: d.Facts["mta_sts_dns_txt_present"] == "true",
	}
}

func inferMatrix(snap correlate.Snapshot) *MatrixHomeserver {
	if d, ok := snap.Docs["matrix/server"]; ok && d.Presence == scan.PresencePresent {
		if name, ok := d.Facts["server_name"]; ok && name != "" {
			return &MatrixHomeserver{Source: "matrix/server", Address: name}
		}
	}
	if d, ok := snap.Docs["matrix/client"]; ok && d.Presence == scan.PresencePresent {
		if url, ok := d.Facts["homeserver_base_url"]; ok && url != "" {
			return &MatrixHomeserver{Source: "matrix/client", Address: url}
		}
	}
	return nil
}

func inferACME(snap correlate.Snapshot) *ACME {
	d, ok := snap.Docs["acme-challenge"]
	return &ACME{Present: ok && d.Presence == scan.PresencePresent}
}

func inferBugBountyProgram(snap correlate.Snapshot) *BugBountyProgram {
	d, ok := snap.Docs["security.txt"]
	if !ok || d.Presence != scan.PresencePresent {
		return nil
	}
	contacts, ok := d.Facts["contact_values"]
	if !ok || contacts == "" {
		return nil
	}
	for _, c := range strings.Split(contacts, "|") {
		c = strings.TrimSpace(c)
		lower := strings.ToLower(c)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			continue
		}
		if platform, matched := MatchBugBountyPlatform(c); matched {
			return &BugBountyProgram{Platform: platform, URL: c}
		}
	}
	return nil
}

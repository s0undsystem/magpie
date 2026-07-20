// Package infer derives a best-effort technology stack summary from
// already-validated well-known content: identity provider, mobile app
// presence, mail security posture, Matrix homeserver, and ACME/certificate
// automation. It never performs additional network requests — everything
// here is read from facts validators already extracted.
package infer

import (
	"strings"

	"github.com/harborproject/magpie/internal/correlate"
	"github.com/harborproject/magpie/internal/scan"
)

// IdentityProvider is the federated identity provider inferred from an
// openid-configuration issuer URL.
type IdentityProvider struct {
	Provider string
	Issuer   string
}

// MobileApp is a mobile app surface discovered via assetlinks.json (Android)
// or apple-app-site-association (iOS).
type MobileApp struct {
	Platform    string // "android" or "ios"
	Identifiers []string
}

// MailSecurity summarizes the mail transport security posture inferred from
// mta-sts.txt and its DNS activation record.
type MailSecurity struct {
	Configured   bool
	Mode         string // "enforce", "testing", "none", or "" if unknown
	DNSActivated bool
}

// MatrixHomeserver is the Matrix homeserver address discovered via
// matrix/server or matrix/client delegation.
type MatrixHomeserver struct {
	Source  string // "matrix/server" or "matrix/client"
	Address string
}

// ACME summarizes whether an ACME HTTP-01 challenge artifact was found.
type ACME struct {
	Present bool
}

// Result is the full inferred stack summary for one scan.
type Result struct {
	IdentityProvider *IdentityProvider
	MobileApps       []MobileApp
	MailSecurity     *MailSecurity
	Matrix           *MatrixHomeserver
	ACME             *ACME
}

// Infer derives a Result from a correlation Snapshot.
func Infer(snap correlate.Snapshot) Result {
	var res Result

	res.IdentityProvider = inferIdentityProvider(snap)
	res.MobileApps = inferMobileApps(snap)
	res.MailSecurity = inferMailSecurity(snap)
	res.Matrix = inferMatrix(snap)
	res.ACME = inferACME(snap)

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

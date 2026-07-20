package infer

import (
	"testing"

	"github.com/harborproject/magpie/internal/correlate"
	"github.com/harborproject/magpie/internal/scan"
)

func TestMatchBugBountyPlatformKnownPlatforms(t *testing.T) {
	cases := map[string]string{
		"https://hackerone.com/github":         "HackerOne",
		"https://bugcrowd.com/example":         "Bugcrowd",
		"https://app.intigriti.com/programs/x": "Intigriti",
		"https://yeswehack.com/programs/x":     "YesWeHack",
		"https://synack.com":                   "Synack",
		"https://openbugbounty.org/x":          "Open Bug Bounty",
		"https://immunefi.com/bounty/x":        "Immunefi",
	}
	for url, want := range cases {
		got, ok := MatchBugBountyPlatform(url)
		if !ok {
			t.Errorf("MatchBugBountyPlatform(%q): no match, want %q", url, want)
			continue
		}
		if got != want {
			t.Errorf("MatchBugBountyPlatform(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestMatchBugBountyPlatformUnknown(t *testing.T) {
	if _, ok := MatchBugBountyPlatform("https://security.example.org/report"); ok {
		t.Error("expected no match for a self-hosted disclosure page")
	}
}

func TestInferBugBountyProgram(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"contact_values": "mailto:security@example.org|https://hackerone.com/example"}),
	})
	res := Infer(s)
	if res.BugBountyProgram == nil {
		t.Fatal("expected a bug bounty program inference")
	}
	if res.BugBountyProgram.Platform != "HackerOne" || res.BugBountyProgram.URL != "https://hackerone.com/example" {
		t.Errorf("BugBountyProgram = %+v", res.BugBountyProgram)
	}
}

func TestInferBugBountyProgramNoMatch(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"contact_values": "mailto:security@example.org"}),
	})
	res := Infer(s)
	if res.BugBountyProgram != nil {
		t.Errorf("expected nil BugBountyProgram, got %+v", res.BugBountyProgram)
	}
}

func TestInferBugBountyProgramNotPresent(t *testing.T) {
	s := snap(map[string]correlate.DocFacts{
		"security.txt": doc(scan.PresenceAbsent, nil),
	})
	res := Infer(s)
	if res.BugBountyProgram != nil {
		t.Errorf("expected nil BugBountyProgram when security.txt is absent, got %+v", res.BugBountyProgram)
	}
}

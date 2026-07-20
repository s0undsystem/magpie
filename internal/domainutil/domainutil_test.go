package domainutil

import "testing"

func TestRegistrableSimple(t *testing.T) {
	if got := Registrable("www.example.org"); got != "example.org" {
		t.Errorf("Registrable() = %q, want example.org", got)
	}
}

func TestRegistrableMultiLabelSuffix(t *testing.T) {
	if got := Registrable("www.example.co.uk"); got != "example.co.uk" {
		t.Errorf("Registrable() = %q, want example.co.uk", got)
	}
}

func TestRegistrableWithPort(t *testing.T) {
	if got := Registrable("example.org:8443"); got != "example.org" {
		t.Errorf("Registrable() = %q, want example.org", got)
	}
}

func TestSameRegistrable(t *testing.T) {
	if !SameRegistrable("a.example.org", "b.example.org") {
		t.Error("expected a.example.org and b.example.org to share a registrable domain")
	}
	if SameRegistrable("example.org", "example.net") {
		t.Error("did not expect example.org and example.net to match")
	}
}

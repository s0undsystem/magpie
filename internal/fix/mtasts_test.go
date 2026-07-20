package fix

import (
	"regexp"
	"testing"
)

var dnsRecordRe = regexp.MustCompile(`^v=STSv1; id=[0-9]{14}$`)

func TestMTASTSDNSRecordFormat(t *testing.T) {
	got := MTASTSDNSRecord(fixedNow)
	if !dnsRecordRe.MatchString(got) {
		t.Errorf("MTASTSDNSRecord() = %q, does not match expected v=STSv1; id=<14 digits>", got)
	}
}

func TestMTASTSDNSRecordDeterministic(t *testing.T) {
	a := MTASTSDNSRecord(fixedNow)
	b := MTASTSDNSRecord(fixedNow)
	if a != b {
		t.Errorf("expected same timestamp to produce the same record, got %q vs %q", a, b)
	}
}

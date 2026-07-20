package render

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/s0undsystem/magpie/internal/report"
)

func TestCSVHeaderAndRow(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, []report.Report{fixtureReport()}, Options{NoTimestamps: true}); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (header + 1 row)", len(records))
	}
	if records[0][0] != "domain" {
		t.Errorf("header[0] = %q, want domain", records[0][0])
	}
	row := records[1]
	if row[0] != "example.org" {
		t.Errorf("row domain = %q", row[0])
	}

	if row[3] != "1" {
		t.Errorf("findings_high = %q, want 1", row[3])
	}
}

func TestCSVMultipleReports(t *testing.T) {
	var buf bytes.Buffer
	r1 := fixtureReport()
	r2 := fixtureReport()
	r2.Domain = "other.example.org"
	if err := CSV(&buf, []report.Report{r1, r2}, Options{NoTimestamps: true}); err != nil {
		t.Fatal(err)
	}
	records, _ := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3 (header + 2 rows)", len(records))
	}
	if records[1][0] != "example.org" || records[2][0] != "other.example.org" {
		t.Errorf("row domains = %q, %q", records[1][0], records[2][0])
	}
}

func TestCSVNoTimestampsOmitsScannedAt(t *testing.T) {
	var buf bytes.Buffer
	CSV(&buf, []report.Report{fixtureReport()}, Options{NoTimestamps: true})
	records, _ := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if records[1][1] != "" {
		t.Errorf("scanned_at = %q, want empty with NoTimestamps", records[1][1])
	}
}

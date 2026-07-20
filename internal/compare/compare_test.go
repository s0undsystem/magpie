package compare

import "testing"

func TestLoadParsesEmbeddedCorpus(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) == 0 {
		t.Fatal("expected a non-empty corpus")
	}
	if c.Methodology == "" {
		t.Error("expected a documented methodology field")
	}
	if c.Description == "" {
		t.Error("expected a description field")
	}
}

func TestLoadIncludesSecurityTxt(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range c.Paths {
		if p.Path == "security.txt" {
			found = true
			if p.PercentPresent < 0 || p.PercentPresent > 100 {
				t.Errorf("security.txt percent_present = %d, want 0-100", p.PercentPresent)
			}
		}
	}
	if !found {
		t.Error("expected security.txt in the reference corpus")
	}
}

func TestRowsMarksTargetPresence(t *testing.T) {
	c := Corpus{Paths: []PathBaseline{
		{Path: "security.txt", PercentPresent: 80},
		{Path: "mta-sts.txt", PercentPresent: 40},
	}}
	rows := Rows(c, map[string]bool{"security.txt": true})
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if !rows[0].TargetPresent {
		t.Error("expected security.txt marked present")
	}
	if rows[1].TargetPresent {
		t.Error("expected mta-sts.txt marked absent")
	}
}

func TestRowsPreservesCorpusOrder(t *testing.T) {
	c := Corpus{Paths: []PathBaseline{
		{Path: "b"}, {Path: "a"}, {Path: "c"},
	}}
	rows := Rows(c, nil)
	want := []string{"b", "a", "c"}
	for i, w := range want {
		if rows[i].Path != w {
			t.Errorf("rows[%d] = %q, want %q", i, rows[i].Path, w)
		}
	}
}

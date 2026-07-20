package finding

import (
	"reflect"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	if !(SeverityInfo.Rank() < SeverityLow.Rank() &&
		SeverityLow.Rank() < SeverityMedium.Rank() &&
		SeverityMedium.Rank() < SeverityHigh.Rank()) {
		t.Fatal("severity ranks are not strictly increasing info < low < medium < high")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high"} {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q) unexpected error: %v", s, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("ParseSeverity(\"critical\") expected error, got nil")
	}
}

func TestConfidenceRank(t *testing.T) {
	if !(ConfidenceInferred.Rank() < ConfidenceLikely.Rank() &&
		ConfidenceLikely.Rank() < ConfidenceCertain.Rank()) {
		t.Fatal("confidence ranks are not strictly increasing inferred < likely < certain")
	}
}

func TestParseConfidence(t *testing.T) {
	for _, c := range []string{"certain", "likely", "inferred"} {
		if _, err := ParseConfidence(c); err != nil {
			t.Errorf("ParseConfidence(%q) unexpected error: %v", c, err)
		}
	}
	if _, err := ParseConfidence("maybe"); err == nil {
		t.Error("ParseConfidence(\"maybe\") expected error, got nil")
	}
}

func TestParseCategory(t *testing.T) {
	for _, c := range []string{"disclosure", "auth", "mail", "mobile", "hygiene"} {
		if _, err := ParseCategory(c); err != nil {
			t.Errorf("ParseCategory(%q) unexpected error: %v", c, err)
		}
	}
	if _, err := ParseCategory("nonsense"); err == nil {
		t.Error("ParseCategory(\"nonsense\") expected error, got nil")
	}
}

func TestSortGroupsByCategoryThenSeverityDescThenIDAsc(t *testing.T) {
	in := []Finding{
		{ID: "CORR-002", Severity: SeverityLow, Category: CategoryMobile},
		{ID: "SECTXT-001", Severity: SeverityHigh, Category: CategoryDisclosure},
		{ID: "SECTXT-003", Severity: SeverityHigh, Category: CategoryDisclosure},
		{ID: "CORR-016", Severity: SeverityHigh, Category: CategoryAuth},
		{ID: "SECTXT-002", Severity: SeverityMedium, Category: CategoryDisclosure},
		{ID: "CORR-021", Severity: SeverityMedium, Category: CategoryMail},
	}
	Sort(in)

	want := []string{
		"SECTXT-001",
		"SECTXT-003",
		"SECTXT-002",
		"CORR-016",
		"CORR-021",
		"CORR-002",
	}
	var got []string
	for _, f := range in {
		got = append(got, f.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Sort() order = %v, want %v", got, want)
	}
}

func TestSortDeterministicAcrossRuns(t *testing.T) {
	base := []Finding{
		{ID: "CORR-024", Severity: SeverityMedium, Category: CategoryHygiene},
		{ID: "CORR-007", Severity: SeverityMedium, Category: CategoryHygiene},
		{ID: "CORR-006", Severity: SeverityLow, Category: CategoryHygiene},
	}
	a := append([]Finding(nil), base...)
	b := append([]Finding(nil), base...)
	Sort(a)
	Sort(b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("two sorts of the same input diverged: %v vs %v", a, b)
	}
}

func TestFilterMinSeverity(t *testing.T) {
	flt := Filter{MinSeverity: SeverityMedium}
	findings := []Finding{
		{ID: "A", Severity: SeverityInfo},
		{ID: "B", Severity: SeverityLow},
		{ID: "C", Severity: SeverityMedium},
		{ID: "D", Severity: SeverityHigh},
	}
	got := flt.Apply(findings)
	if len(got) != 2 || got[0].ID != "C" || got[1].ID != "D" {
		t.Errorf("Apply() = %+v, want [C D]", got)
	}
}

func TestFilterMinConfidence(t *testing.T) {
	flt := Filter{MinConfidence: ConfidenceCertain}
	findings := []Finding{
		{ID: "A", Confidence: ConfidenceInferred},
		{ID: "B", Confidence: ConfidenceLikely},
		{ID: "C", Confidence: ConfidenceCertain},
	}
	got := flt.Apply(findings)
	if len(got) != 1 || got[0].ID != "C" {
		t.Errorf("Apply() = %+v, want [C]", got)
	}
}

func TestFilterCategory(t *testing.T) {
	flt := Filter{Categories: []Category{CategoryMail, CategoryAuth}}
	findings := []Finding{
		{ID: "A", Category: CategoryDisclosure},
		{ID: "B", Category: CategoryMail},
		{ID: "C", Category: CategoryAuth},
		{ID: "D", Category: CategoryMobile},
	}
	got := flt.Apply(findings)
	if len(got) != 2 || got[0].ID != "B" || got[1].ID != "C" {
		t.Errorf("Apply() = %+v, want [B C]", got)
	}
}

func TestFilterEmptyMatchesEverything(t *testing.T) {
	var flt Filter
	findings := []Finding{
		{ID: "A", Severity: SeverityInfo, Confidence: ConfidenceInferred, Category: CategoryHygiene},
	}
	if got := flt.Apply(findings); len(got) != 1 {
		t.Errorf("Apply() with zero-value Filter = %+v, want all findings passed through", got)
	}
}

func TestGroupByCategoryOrder(t *testing.T) {
	findings := []Finding{
		{ID: "H1", Severity: SeverityHigh, Category: CategoryHygiene},
		{ID: "D1", Severity: SeverityHigh, Category: CategoryDisclosure},
		{ID: "M1", Severity: SeverityHigh, Category: CategoryMobile},
	}
	Sort(findings)
	groups := GroupByCategory(findings)
	var order []Category
	for _, g := range groups {
		order = append(order, g.Category)
	}
	want := []Category{CategoryDisclosure, CategoryMobile, CategoryHygiene}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("GroupByCategory() category order = %v, want %v", order, want)
	}
}

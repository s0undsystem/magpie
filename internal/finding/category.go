package finding

import "fmt"

// Category groups findings by the kind of surface they concern.
type Category string

const (
	CategoryDisclosure Category = "disclosure"
	CategoryAuth       Category = "auth"
	CategoryMail       Category = "mail"
	CategoryMobile     Category = "mobile"
	CategoryHygiene    Category = "hygiene"
)

// categoryOrder is the canonical display order for grouping findings by
// category, matching the order categories are introduced in the spec.
var categoryOrder = map[Category]int{
	CategoryDisclosure: 0,
	CategoryAuth:       1,
	CategoryMail:       2,
	CategoryMobile:     3,
	CategoryHygiene:    4,
}

// Rank returns the canonical display order of the category. Unknown
// categories sort last.
func (c Category) Rank() int {
	if r, ok := categoryOrder[c]; ok {
		return r
	}
	return len(categoryOrder)
}

// Valid reports whether c is one of the defined categories.
func (c Category) Valid() bool {
	_, ok := categoryOrder[c]
	return ok
}

// ParseCategory parses a category from user input (e.g. a CLI flag value).
func ParseCategory(s string) (Category, error) {
	c := Category(s)
	if !c.Valid() {
		return "", fmt.Errorf("invalid category %q: must be one of disclosure, auth, mail, mobile, hygiene", s)
	}
	return c, nil
}

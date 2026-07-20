package finding

import "fmt"

type Category string

const (
	CategoryDisclosure Category = "disclosure"
	CategoryAuth       Category = "auth"
	CategoryMail       Category = "mail"
	CategoryMobile     Category = "mobile"
	CategoryHygiene    Category = "hygiene"
)

var categoryOrder = map[Category]int{
	CategoryDisclosure: 0,
	CategoryAuth:       1,
	CategoryMail:       2,
	CategoryMobile:     3,
	CategoryHygiene:    4,
}

func (c Category) Rank() int {
	if r, ok := categoryOrder[c]; ok {
		return r
	}
	return len(categoryOrder)
}

func (c Category) Valid() bool {
	_, ok := categoryOrder[c]
	return ok
}

func ParseCategory(s string) (Category, error) {
	c := Category(s)
	if !c.Valid() {
		return "", fmt.Errorf("invalid category %q: must be one of disclosure, auth, mail, mobile, hygiene", s)
	}
	return c, nil
}

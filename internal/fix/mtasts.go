package fix

import (
	"fmt"
	"time"
)

func MTASTSDNSRecord(now time.Time) string {
	return fmt.Sprintf("v=STSv1; id=%s", now.UTC().Format("20060102150405"))
}

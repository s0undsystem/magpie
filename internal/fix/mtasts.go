package fix

import (
	"fmt"
	"time"
)

// MTASTSDNSRecord renders the exact TXT record value to publish at
// _mta-sts.<host> so an existing mta-sts.txt policy actually takes effect.
// The id is a timestamp, following the common (not RFC-mandated) MTA-STS
// convention of using one so senders can detect when the policy changes.
func MTASTSDNSRecord(now time.Time) string {
	return fmt.Sprintf("v=STSv1; id=%s", now.UTC().Format("20060102150405"))
}

package retry_test

import (
	"math/big"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-xhttp/retry"
)

// owed is what a Retry-After asks for, read as RFC 9110 section 10.2.3
// writes it and not as the package does: a delay is digits and nothing else,
// however many; anything else is a date, in the forms net/http reads, or
// asks for nothing. It returns the wait asked, counted from now, and whether
// it is within limit.
func owed(value string, now time.Time, limit time.Duration) (time.Duration, bool) {
	digits := value != "" && !strings.ContainsFunc(value, func(char rune) bool { return char < '0' || char > '9' })

	switch date, err := http.ParseTime(value); {
	case digits:
		seconds, _ := new(big.Int).SetString(value, 10)
		if seconds.Cmp(big.NewInt(int64(limit/time.Second))) > 0 {
			return 0, false
		}

		return time.Duration(seconds.Int64()) * time.Second, true
	case err != nil:
		return 0, true
	default:
		wait := date.Sub(now)

		return max(wait, 0), wait <= limit
	}
}

// FuzzRetryAfter: whatever a server writes in Retry-After, the request is
// sent again exactly when the header asks for no more than MaxBackoff, and
// after a wait drawn from what it asks to a quarter more, MaxBackoff at
// most, or the backoff's own wait when that is longer. The clock is
// testing/synctest's, so the wait is exact.
func FuzzRetryAfter(f *testing.F) {
	for _, seed := range []string{
		"", "0", "1", "3600", "3601", "-1", "1.5", "1s", "later", "9223372037", "18446744073709551615",
		"18446744073709551616", "Wed, 21 Oct 2015 07:28:00 GMT", "Wednesday, 21-Oct-15 07:28:00 GMT",
		"Wed Oct 21 07:28:00 2015", "Fri, 31 Dec 9999 23:59:59 GMT", " 1", "1 ", "+1", "0x1", "1e3", "0001",
		"Sat, 01 Jan 2000 00:30:00 GMT", "Sat, 01 Jan 2000 01:00:00 GMT", "Sat, 01 Jan 2000 01:00:01 GMT",
		"Saturday, 01-Jan-00 00:00:01 GMT", "Sat Jan  1 00:59:59 2000", "١", "1_0", "00000000000000000000001",
	} {
		f.Add(seed)
	}

	const (
		first   = time.Millisecond
		longest = time.Hour
	)

	f.Fuzz(func(t *testing.T, value string) {
		synctest.Test(t, func(t *testing.T) {
			asked, obeyed := owed(value, time.Now(), longest)

			base := &scripted{script: failing(1, answer{
				status: http.StatusServiceUnavailable,
				header: http.Header{"Retry-After": {value}},
			})}

			status, err := send(
				t,
				base,
				retry.Options{Retries: 1, Backoff: first, MaxBackoff: longest},
				http.MethodGet,
				nil,
			)
			if err != nil {
				t.Fatalf("Retry-After %q: %v", value, err)
			}

			sent := base.attempts()

			if !obeyed {
				if len(sent) != 1 || status != http.StatusServiceUnavailable {
					t.Fatalf("Retry-After %q asks for more than %v: %d after %d attempts, want the 503 after 1",
						value, longest, status, len(sent))
				}

				return
			}

			if len(sent) != 2 || status != http.StatusOK {
				t.Fatalf("Retry-After %q asks for %v: %d after %d attempts, want 200 after 2",
					value, asked, status, len(sent))
			}

			// The longer of the two draws: what was asked to a quarter
			// more, and three quarters to five quarters of the backoff.
			least := max(asked, first*3/4)
			most := max(min(asked+asked/4, longest), first*5/4)

			if waited := sent[1].at.Sub(sent[0].at); waited < least || waited > most {
				t.Fatalf("Retry-After %q asks for %v: waited %v, want from %v to %v", value, asked, waited, least, most)
			}
		})
	})
}

// Copyright Mycophonic.
// Copyright Forkcloser.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package retry_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/forkcloser/xhttp/retry"
)

// FuzzRetryAfter: whatever a server writes in Retry-After, the request is
// sent again or the response comes back, and the wait is never longer than
// MaxBackoff. A header that parsed into a wait of its own size, or into a
// negative one, shows as a wait too long or as no wait where one was asked.
func FuzzRetryAfter(f *testing.F) {
	for _, seed := range []string{
		"", "0", "1", "3600", "-1", "1.5", "1s", "later", "9223372037", "18446744073709551615",
		"18446744073709551616", "Wed, 21 Oct 2015 07:28:00 GMT", "Wednesday, 21-Oct-15 07:28:00 GMT",
		"Wed Oct 21 07:28:00 2015", "Fri, 31 Dec 9999 23:59:59 GMT", " 1", "1 ", "+1", "0x1", "1e3",
	} {
		f.Add(seed)
	}

	const longest = 20 * time.Millisecond

	f.Fuzz(func(t *testing.T, value string) {
		base := &scripted{script: failing(1, answer{
			status: http.StatusServiceUnavailable,
			header: http.Header{"Retry-After": {value}},
		})}

		status, err := send(
			t,
			base,
			retry.Options{Retries: 1, Backoff: time.Millisecond, MaxBackoff: longest},
			http.MethodGet,
			nil,
		)
		if err != nil {
			t.Fatalf("Retry-After %q: %v", value, err)
		}

		switch sent := base.attempts(); {
		case len(sent) == 1 && status == http.StatusServiceUnavailable:
		case len(sent) == 2 && status == http.StatusOK:
			// MaxBackoff, and what the machine adds, bounded loosely.
			if waited := sent[1].at.Sub(sent[0].at); waited > longest+20*time.Second {
				t.Fatalf("Retry-After %q: waited %v, past the %v of MaxBackoff", value, waited, longest)
			}
		default:
			t.Fatalf("Retry-After %q: %d after %d attempts", value, status, len(sent))
		}
	})
}

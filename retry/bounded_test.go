// Copyright Mycophonic.
// Copyright Forkcloser.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package retry_test

// The walk within the bound: every method of RFC 9110 and one outside it,
// with and without each idempotency key, against a status and an error;
// every status from 100 to 599; every form of Retry-After, at MaxBackoff and
// one second past it; the wait before each of the first retries.

import (
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/forkcloser/xhttp/retry"
)

// TestMethods: an idempotent method is sent again after a 503 and after an
// error; any other is sent once, unless it carries an idempotency key.
func TestMethods(t *testing.T) {
	t.Parallel()

	idempotent := []string{
		http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete,
	}

	keys := map[string]func(*http.Request){
		"no key":            nil,
		"Idempotency-Key":   func(req *http.Request) { req.Header.Set("Idempotency-Key", "one") },
		"X-Idempotency-Key": func(req *http.Request) { req.Header.Set("X-Idempotency-Key", "one") },
		"a key of no value": func(req *http.Request) { req.Header["Idempotency-Key"] = nil },
		"another header":    func(req *http.Request) { req.Header.Set("Idempotency", "one") },
	}

	for _, method := range append(idempotent, http.MethodPost, http.MethodPatch, http.MethodConnect, "PROPFIND", "get") {
		for name, key := range keys {
			again := slices.Contains(idempotent, method) || name != "no key" && name != "another header"

			for cause, failure := range map[string]answer{
				"a 503":    {status: http.StatusServiceUnavailable},
				"an error": {err: errFlaky},
			} {
				base := &scripted{script: failing(1, failure)}

				_, _ = send(t, base, quick(1), method, key)

				if want := map[bool]int{true: 2, false: 1}[again]; len(base.attempts()) != want {
					t.Errorf(
						"%s with %s, after %s: %d attempts, want %d",
						method,
						name,
						cause,
						len(base.attempts()),
						want,
					)
				}
			}
		}
	}
}

// TestStatuses: of every status, the five that say the server could not
// answer now are asked again.
func TestStatuses(t *testing.T) {
	t.Parallel()

	again := []int{
		http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout,
	}

	for status := 100; status <= 599; status++ {
		base := &scripted{script: failing(1, answer{status: status})}

		got, err := send(t, base, quick(1), http.MethodGet, nil)
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}

		want, attempts := status, 1
		if slices.Contains(again, status) {
			want, attempts = http.StatusOK, 2
		}

		if got != want || len(base.attempts()) != attempts {
			t.Errorf(
				"status %d: %d after %d attempts; want %d after %d",
				status,
				got,
				len(base.attempts()),
				want,
				attempts,
			)
		}
	}
}

// TestRetryAfter: what a Retry-After asks for is waited when it is longer
// than the backoff and no longer than MaxBackoff; past MaxBackoff the
// response comes back; what is no number of seconds and no date asks for
// nothing.
func TestRetryAfter(t *testing.T) {
	t.Parallel()

	const longest = 2 * time.Second

	date := func(in time.Duration) string { return time.Now().Add(in).UTC().Format(http.TimeFormat) }

	for name, header := range map[string]struct {
		value string
		again bool
		least time.Duration
	}{
		"no seconds":                     {"0", true, 0},
		"one second":                     {"1", true, time.Second},
		"MaxBackoff":                     {"2", true, 2 * time.Second},
		"a second past MaxBackoff":       {"3", false, 0},
		"an hour":                        {"3600", false, 0},
		"past what a duration holds":     {"9223372037", false, 0},
		"the largest 64-bit number":      {"18446744073709551615", false, 0},
		"past what 64 bits hold":         {"18446744073709551616", false, 0},
		"a date in the past":             {date(-time.Hour), true, 0},
		"a date an hour away":            {date(time.Hour), false, 0},
		"a negative number":              {"-1", true, 0},
		"a fraction":                     {"1.5", true, 0},
		"a number with a unit":           {"1s", true, 0},
		"words":                          {"later", true, 0},
		"an obsolete date, RFC 850":      {time.Now().Add(-time.Hour).UTC().Format(time.RFC850), true, 0},
		"an obsolete date, asctime":      {time.Now().Add(-time.Hour).UTC().Format(time.ANSIC), true, 0},
		"a date a moment within the max": {date(1500 * time.Millisecond), true, 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := &scripted{script: failing(1, answer{
				status: http.StatusTooManyRequests,
				header: http.Header{"Retry-After": {header.value}},
			})}

			status, err := send(
				t,
				base,
				retry.Options{Retries: 1, Backoff: time.Millisecond, MaxBackoff: longest},
				http.MethodGet,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}

			sent := base.attempts()

			if !header.again {
				if status != http.StatusTooManyRequests || len(sent) != 1 {
					t.Fatalf(
						"Retry-After %q: %d after %d attempts; want the 429 after 1",
						header.value,
						status,
						len(sent),
					)
				}

				return
			}

			if status != http.StatusOK || len(sent) != 2 {
				t.Fatalf("Retry-After %q: %d after %d attempts; want 200 after 2", header.value, status, len(sent))
			}

			// A timer never fires early, so the least wait is exact; the most is
			// MaxBackoff and what the machine adds, bounded loosely.
			if waited := sent[1].at.Sub(sent[0].at); waited < header.least || waited > longest+20*time.Second {
				t.Errorf(
					"Retry-After %q: waited %v, want at least %v and about %v at most",
					header.value,
					waited,
					header.least,
					longest,
				)
			}
		})
	}
}

// TestBackoff: the wait before each retry is at least three quarters of
// Backoff doubled each time, and MaxBackoff once that is reached.
func TestBackoff(t *testing.T) {
	t.Parallel()

	const (
		first   = 40 * time.Millisecond
		longest = 100 * time.Millisecond
		retries = 4
	)

	base := &scripted{script: failing(retries, answer{err: errFlaky})}

	if status, err := send(
		t,
		base,
		retry.Options{Retries: retries, Backoff: first, MaxBackoff: longest},
		http.MethodGet,
		nil,
	); err != nil ||
		status != http.StatusOK {
		t.Fatalf("%d, %v; want 200", status, err)
	}

	sent := base.attempts()
	if len(sent) != retries+1 {
		t.Fatalf("%d attempts, want %d", len(sent), retries+1)
	}

	// 40ms, 80ms, then 160ms and 320ms cut to the 100ms of MaxBackoff; a
	// quarter less at most, and a timer never fires early.
	for index, least := range []time.Duration{30 * time.Millisecond, 60 * time.Millisecond, 75 * time.Millisecond, 75 * time.Millisecond} {
		if waited := sent[index+1].at.Sub(sent[index].at); waited < least {
			t.Errorf("the wait before retry %d was %v, want %v at least", index+1, waited, least)
		}
	}

	// Four waits of MaxBackoff at most, and what the machine adds, bounded loosely.
	if whole := sent[retries].at.Sub(sent[0].at); whole > retries*longest+20*time.Second {
		t.Errorf("the %d retries took %v, with waits of %v at most", retries, whole, longest)
	}
}

// TestBackoffAtTheEdges: a Backoff past MaxBackoff waits as MaxBackoff does,
// and the largest durations double into no negative wait.
func TestBackoffAtTheEdges(t *testing.T) {
	t.Parallel()

	const (
		longest = 20 * time.Millisecond
		least   = 15 * time.Millisecond // a quarter less than MaxBackoff
	)

	for name, backoff := range map[string]time.Duration{
		"a Backoff past MaxBackoff": time.Hour,
		"the largest Backoff":       time.Duration(1<<63 - 1),
	} {
		base := &scripted{script: failing(3, answer{err: errFlaky})}

		if status, err := send(
			t,
			base,
			retry.Options{Retries: 3, Backoff: backoff, MaxBackoff: longest},
			http.MethodGet,
			nil,
		); err != nil ||
			status != http.StatusOK {
			t.Fatalf("%s: %d, %v; want 200", name, status, err)
		}

		sent := base.attempts()
		for index := range len(sent) - 1 {
			if waited := sent[index+1].at.Sub(sent[index].at); waited < least {
				t.Errorf("%s: the wait before retry %d was %v, want %v at least", name, index+1, waited, least)
			}
		}
	}

	// The largest MaxBackoff, where a jittered wait would not fit a duration:
	// the wait is still the Backoff's, not a negative one that does not wait.
	base := &scripted{script: failing(2, answer{err: errFlaky})}
	options := retry.Options{Retries: 2, Backoff: 20 * time.Millisecond, MaxBackoff: time.Duration(1<<63 - 1)}

	if status, err := send(t, base, options, http.MethodGet, nil); err != nil || status != http.StatusOK {
		t.Fatalf("the largest MaxBackoff: %d, %v; want 200", status, err)
	}

	sent := base.attempts()
	for index, floor := range []time.Duration{15 * time.Millisecond, 30 * time.Millisecond} {
		if waited := sent[index+1].at.Sub(sent[index].at); waited < floor {
			t.Errorf(
				"the largest MaxBackoff: the wait before retry %d was %v, want %v at least",
				index+1,
				waited,
				floor,
			)
		}
	}
}

// TestRetries: a request is sent again Retries times, and no more.
func TestRetries(t *testing.T) {
	t.Parallel()

	for retries := range 5 {
		base := &scripted{script: failing(retries+3, answer{status: http.StatusServiceUnavailable})}

		status, err := send(t, base, quick(retries), http.MethodGet, nil)
		if err != nil || status != http.StatusServiceUnavailable || len(base.attempts()) != retries+1 {
			t.Errorf("Retries %s: %d, %v after %d attempts; want the 503 after %d",
				strconv.Itoa(retries), status, err, len(base.attempts()), retries+1)
		}
	}
}

// TestTheDefaults: Options that name no Backoff wait DefaultBackoff, a
// quarter less at most, and Options that name no MaxBackoff obey a
// Retry-After up to DefaultMaxBackoff and no further.
func TestTheDefaults(t *testing.T) {
	t.Parallel()

	base := &scripted{script: failing(1, answer{err: errFlaky})}

	if status, err := send(
		t,
		base,
		retry.Options{Retries: 1},
		http.MethodGet,
		nil,
	); err != nil ||
		status != http.StatusOK {
		t.Fatalf("%d, %v; want 200", status, err)
	}

	sent := base.attempts()
	if waited := sent[1].at.Sub(sent[0].at); waited < retry.DefaultBackoff*3/4 {
		t.Errorf("with no Backoff named the wait was %v, want %v at least", waited, retry.DefaultBackoff*3/4)
	}

	for asked, again := range map[time.Duration]bool{
		time.Second:                           true,
		retry.DefaultMaxBackoff + time.Second: false,
	} {
		base = &scripted{script: failing(1, answer{
			status: http.StatusServiceUnavailable,
			header: http.Header{"Retry-After": {strconv.Itoa(int(asked / time.Second))}},
		})}

		status, err := send(t, base, retry.Options{Retries: 1, Backoff: time.Millisecond}, http.MethodGet, nil)
		if err != nil {
			t.Fatal(err)
		}

		if want := map[bool]int{true: 2, false: 1}[again]; len(base.attempts()) != want {
			t.Errorf("with no MaxBackoff named, a Retry-After of %v: %d after %d attempts, want %d attempts",
				asked, status, len(base.attempts()), want)
		}
	}
}

package retry_test

// The walk within the bound: every method of RFC 9110 and one outside it,
// with and without each idempotency key, against a status and an error;
// every status from 100 to 599; every form of Retry-After, at MaxBackoff and
// one second past it; the wait before each of the first retries. The waits
// are on testing/synctest's clock, where they are exact and take no time.

import (
	"net/http"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/xhttp/retry"
)

// TestMethods: an idempotent method is sent again after a 503 and after an
// error; any other is sent once, unless it carries an idempotency key.
func TestMethods(t *testing.T) {
	t.Parallel()

	// A request with no method is a GET (net/http, Request.Method: "For
	// client requests, an empty string means GET").
	idempotent := []string{
		http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete, "",
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

				// As written: http.NewRequest fills an empty method in.
				_, _ = send(t, base, quick(1), method, func(req *http.Request) {
					req.Method = method

					if key != nil {
						key(req)
					}
				})

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

// TestStatuses: of every status, the six that say the server could not
// answer now are asked again.
func TestStatuses(t *testing.T) {
	t.Parallel()

	again := []int{
		http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
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

// clocked sends one GET for each round through a transport with options,
// over a base that answers from script, on testing/synctest's clock: time
// passes in the transport's own waits and nowhere else, so each wait is
// exact. It returns the waits of each round, one before each retry.
func clocked(t *testing.T, rounds int, options retry.Options, script []answer) [][]time.Duration {
	t.Helper()

	waited := make([][]time.Duration, 0, rounds)

	synctest.Test(t, func(t *testing.T) {
		for range rounds {
			base := &scripted{script: script}

			if _, err := send(t, base, options, http.MethodGet, nil); err != nil {
				t.Fatal(err)
			}

			sent := base.attempts()
			round := make([]time.Duration, 0, len(sent))

			for index := range len(sent) - 1 {
				round = append(round, sent[index+1].at.Sub(sent[index].at))
			}

			waited = append(waited, round)
		}
	})

	return waited
}

// before is the wait before the nth retry, the first being 1, in every
// round.
func before(t *testing.T, waited [][]time.Duration, nth int) []time.Duration {
	t.Helper()

	waits := make([]time.Duration, 0, len(waited))

	for _, round := range waited {
		if len(round) < nth {
			t.Fatalf("a round made %d retries, want %d at least", len(round), nth)
		}

		waits = append(waits, round[nth-1])
	}

	return waits
}

// drawn holds every wait to no less than least and to under most, and to
// both ends of that: of several hundred waits drawn evenly, one comes within
// a tenth of each end.
func drawn(t *testing.T, what string, waits []time.Duration, least, most time.Duration) {
	t.Helper()

	lowest, highest, margin := slices.Min(waits), slices.Max(waits), (most-least)/10

	if lowest < least || highest >= most {
		t.Errorf("%s: the waits go from %v to %v, want all from %v and under %v", what, lowest, highest, least, most)
	}

	if lowest > least+margin || highest < most-margin {
		t.Errorf("%s: the waits go from %v to %v, and do not reach both ends of %v to %v",
			what, lowest, highest, least, most)
	}
}

// TestRetryAfter: what a Retry-After asks for is waited, and a quarter more
// at most, when it is longer than the backoff and no longer than MaxBackoff;
// past MaxBackoff the response comes back; what is no number of seconds and
// no date asks for nothing, and the wait is the backoff's.
func TestRetryAfter(t *testing.T) {
	t.Parallel()

	const (
		first   = time.Millisecond
		longest = 2 * time.Second
	)

	text := func(value string) func() string { return func() string { return value } }
	in := func(wait time.Duration, layout string) func() string {
		return func() string { return time.Now().Add(wait).UTC().Format(layout) }
	}

	cases := map[string]struct {
		value func() string
		again bool
		asked time.Duration
	}{
		"no header value":                  {text(""), true, 0},
		"no seconds":                       {text("0"), true, 0},
		"one second":                       {text("1"), true, time.Second},
		"one second, with zeros before":    {text("0001"), true, time.Second},
		"MaxBackoff":                       {text("2"), true, 2 * time.Second},
		"a second past MaxBackoff":         {text("3"), false, 0},
		"an hour":                          {text("3600"), false, 0},
		"past what a duration holds":       {text("9223372037"), false, 0},
		"the largest 64-bit number":        {text("18446744073709551615"), false, 0},
		"past what 64 bits hold":           {text("18446744073709551616"), false, 0},
		"a negative number":                {text("-1"), true, 0},
		"a fraction":                       {text("1.5"), true, 0},
		"a number with a unit":             {text("1s"), true, 0},
		"words":                            {text("later"), true, 0},
		"a date in the past":               {in(-time.Hour, http.TimeFormat), true, 0},
		"a date that is now":               {in(0, http.TimeFormat), true, 0},
		"a date a second away":             {in(time.Second, http.TimeFormat), true, time.Second},
		"a date at MaxBackoff":             {in(2*time.Second, http.TimeFormat), true, 2 * time.Second},
		"a date a second past MaxBackoff":  {in(3*time.Second, http.TimeFormat), false, 0},
		"a date an hour away":              {in(time.Hour, http.TimeFormat), false, 0},
		"an obsolete date, RFC 850":        {in(-time.Hour, time.RFC850), true, 0},
		"an obsolete date, asctime":        {in(-time.Hour, time.ANSIC), true, 0},
		"RFC 850, a second away":           {in(time.Second, time.RFC850), true, time.Second},
		"asctime, a second away":           {in(time.Second, time.ANSIC), true, time.Second},
		"asctime, a second past the limit": {in(3*time.Second, time.ANSIC), false, 0},
	}

	synctest.Test(t, func(t *testing.T) {
		for name, header := range cases {
			// From a whole second: a date is written to the second, and
			// what it asks for is counted from the moment it is read.
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))

			value := header.value()
			base := &scripted{script: failing(1, answer{
				status: http.StatusTooManyRequests,
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
				t.Fatal(err)
			}

			sent := base.attempts()

			if !header.again {
				if status != http.StatusTooManyRequests || len(sent) != 1 {
					t.Errorf("%s, %q: %d after %d attempts; want the 429 after 1", name, value, status, len(sent))
				}

				continue
			}

			if status != http.StatusOK || len(sent) != 2 {
				t.Errorf("%s, %q: %d after %d attempts; want 200 after 2", name, value, status, len(sent))

				continue
			}

			switch waited := sent[1].at.Sub(sent[0].at); {
			case header.asked == 0 && (waited < first*3/4 || waited >= first*5/4):
				t.Errorf("%s, %q: waited %v, want the backoff's %v, a quarter less or more", name, value, waited, first)
			case header.asked == longest && waited != longest:
				t.Errorf("%s, %q: waited %v, want the %v of MaxBackoff", name, value, waited, longest)
			case header.asked != 0 && (waited < header.asked || waited > min(header.asked*5/4, longest)):
				t.Errorf("%s, %q: waited %v, want %v and a quarter more at most", name, value, waited, header.asked)
			}
		}
	})
}

// TestARetryAfterIsSpread: the wait a Retry-After asks for is drawn from
// what it asks to a quarter more, and to MaxBackoff when that is less, with
// none on MaxBackoff itself.
func TestARetryAfterIsSpread(t *testing.T) {
	t.Parallel()

	const (
		longest = time.Minute
		rounds  = 500
	)

	for asked, most := range map[time.Duration]time.Duration{
		4 * time.Second:  5 * time.Second,
		48 * time.Second: longest,
		50 * time.Second: longest,
	} {
		waited := clocked(
			t,
			rounds,
			retry.Options{Retries: 1, Backoff: time.Millisecond, MaxBackoff: longest},
			failing(1, answer{
				status: http.StatusServiceUnavailable,
				header: http.Header{"Retry-After": {strconv.Itoa(int(asked / time.Second))}},
			}),
		)

		drawn(t, "a Retry-After of "+asked.String(), before(t, waited, 1), asked, most)
	}
}

// TestTheLongerOfBackoffAndRetryAfterIsWaited: a Retry-After that asks for
// less than the backoff does not shorten it.
func TestTheLongerOfBackoffAndRetryAfterIsWaited(t *testing.T) {
	t.Parallel()

	const first = 8 * time.Second

	waited := clocked(
		t,
		500,
		retry.Options{Retries: 1, Backoff: first, MaxBackoff: time.Minute},
		failing(1, answer{
			status: http.StatusServiceUnavailable,
			header: http.Header{"Retry-After": {"1"}},
		}),
	)

	drawn(t, "a Retry-After of a second, a Backoff of eight", before(t, waited, 1), first*3/4, first*5/4)
}

// TestBackoff: the wait before each retry is drawn between three quarters
// and five quarters of Backoff doubled each time, or to MaxBackoff when that
// is less, and never on it.
func TestBackoff(t *testing.T) {
	t.Parallel()

	const (
		first   = 40 * time.Millisecond
		longest = 100 * time.Millisecond
		retries = 4
		rounds  = 500
	)

	waited := clocked(
		t,
		rounds,
		retry.Options{Retries: retries, Backoff: first, MaxBackoff: longest},
		failing(retries, answer{err: errFlaky}),
	)

	// 40ms, 80ms, then 160ms and 320ms cut to the 100ms of MaxBackoff.
	drawn(t, "retry 1", before(t, waited, 1), 30*time.Millisecond, 50*time.Millisecond)
	drawn(t, "retry 2", before(t, waited, 2), 60*time.Millisecond, 100*time.Millisecond)
	drawn(t, "retry 3", before(t, waited, 3), 75*time.Millisecond, longest)
	drawn(t, "retry 4", before(t, waited, 4), 75*time.Millisecond, longest)
}

// TestBackoffAtTheEdges: a Backoff past MaxBackoff waits as MaxBackoff does;
// the largest MaxBackoff leaves the first waits as they are; and a wait
// doubled more times than a duration has bits is still MaxBackoff's.
func TestBackoffAtTheEdges(t *testing.T) {
	t.Parallel()

	const (
		longest = 20 * time.Millisecond
		largest = time.Duration(1<<63 - 1)
		rounds  = 500
	)

	for name, backoff := range map[string]time.Duration{
		"a Backoff past MaxBackoff": time.Hour,
		"the largest Backoff":       largest,
	} {
		waited := clocked(
			t,
			rounds,
			retry.Options{Retries: 2, Backoff: backoff, MaxBackoff: longest},
			failing(2, answer{err: errFlaky}),
		)

		drawn(t, name+", retry 1", before(t, waited, 1), longest*3/4, longest)
		drawn(t, name+", retry 2", before(t, waited, 2), longest*3/4, longest)
	}

	waited := clocked(
		t,
		rounds,
		retry.Options{Retries: 2, Backoff: 20 * time.Millisecond, MaxBackoff: largest},
		failing(2, answer{err: errFlaky}),
	)

	drawn(t, "the largest MaxBackoff, retry 1", before(t, waited, 1), 15*time.Millisecond, 25*time.Millisecond)
	drawn(t, "the largest MaxBackoff, retry 2", before(t, waited, 2), 30*time.Millisecond, 50*time.Millisecond)

	// A millisecond doubled 79 times is past what a duration holds, and
	// past it twice over.
	const doublings = 80

	waited = clocked(
		t,
		rounds/10,
		retry.Options{Retries: doublings, Backoff: time.Millisecond, MaxBackoff: longest},
		failing(doublings, answer{err: errFlaky}),
	)

	// 16ms is the last wait under MaxBackoff: every wait after it, of every
	// round, is MaxBackoff's.
	var late []time.Duration

	for nth := 6; nth <= doublings; nth++ {
		late = append(late, before(t, waited, nth)...)
	}

	drawn(t, "retries 6 to 80", late, longest*3/4, longest)
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

// TestTheDefaults: Options that name no Backoff wait half a second, a
// quarter less or more, and Options that name no MaxBackoff obey a
// Retry-After of 30 seconds and none of 31, as the docs say.
func TestTheDefaults(t *testing.T) {
	t.Parallel()

	const rounds = 500

	waited := clocked(t, rounds, retry.Options{Retries: 1}, failing(1, answer{err: errFlaky}))

	drawn(t, "no Backoff named", before(t, waited, 1), 375*time.Millisecond, 625*time.Millisecond)

	for asked, again := range map[time.Duration]bool{
		29 * time.Second: true,
		30 * time.Second: true,
		31 * time.Second: false,
	} {
		waited = clocked(t, 1, retry.Options{Retries: 1, Backoff: time.Millisecond}, failing(1, answer{
			status: http.StatusServiceUnavailable,
			header: http.Header{"Retry-After": {strconv.Itoa(int(asked / time.Second))}},
		}))

		const longest = 30 * time.Second

		switch {
		case !again && len(waited[0]) != 0:
			t.Errorf("with no MaxBackoff named, a Retry-After of %v was obeyed, with a wait of %v", asked, waited[0])
		case again && (len(waited[0]) != 1 || waited[0][0] < asked || waited[0][0] > longest):
			t.Errorf("with no MaxBackoff named, a Retry-After of %v: waits %v, want one from that to %v",
				asked, waited[0], longest)
		}
	}
}

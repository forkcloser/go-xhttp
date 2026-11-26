package retry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/forkcloser/xhttp"
)

// The Backoff and the MaxBackoff of Options that name none.
const (
	defaultBackoff    = 500 * time.Millisecond
	defaultMaxBackoff = 30 * time.Second
)

// Options is what varies between retrying transports. The zero value sends
// each request once.
type Options struct {
	// Retries is how many times at most a request is sent again. Zero
	// sends each request once.
	Retries int
	// Backoff is the wait before the first retry. Zero is half a second.
	Backoff time.Duration
	// MaxBackoff is the longest wait before a retry, and the longest
	// Retry-After obeyed. Zero is 30 seconds.
	MaxBackoff time.Duration
}

// NewTransport returns a transport that carries each request through base,
// and again as the package doc says. Its CloseIdleConnections forwards to
// base. It panics on a nil base, and on Options with a negative field: a
// count or a wait below zero has no meaning to give.
func NewTransport(base http.RoundTripper, options Options) http.RoundTripper {
	if base == nil {
		panic("retry: NewTransport needs a transport to carry the attempts")
	}

	if options.Retries < 0 || options.Backoff < 0 || options.MaxBackoff < 0 {
		panic(fmt.Sprintf("retry: NewTransport needs Options with no negative field, and was given %+v", options))
	}

	made := &transport{
		base:       base,
		retries:    options.Retries,
		backoff:    options.Backoff,
		maxBackoff: options.MaxBackoff,
	}

	if made.backoff == 0 {
		made.backoff = defaultBackoff
	}

	if made.maxBackoff == 0 {
		made.maxBackoff = defaultMaxBackoff
	}

	return made
}

type transport struct {
	base       http.RoundTripper
	retries    int
	backoff    time.Duration
	maxBackoff time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Asked before the request is the base's: once it is, a read of its
	// body may be writing the Trailer this looks at. A request with no URL
	// or no header map is the base's to refuse, once.
	if req.URL == nil || req.Header == nil || !rewindable(req) {
		return t.base.RoundTrip(req) //nolint:wrapcheck // the base's own error, unchanged
	}

	resp, err := t.base.RoundTrip(req)

	for retry := 1; retry <= t.retries; retry++ {
		wait, again := t.wait(req, resp, err, retry)
		if !again {
			break
		}

		// Before the answer in hand is given up: a request whose body cannot
		// be read again after all keeps the answer it has.
		sent, rewindErr := rewound(req)
		if rewindErr != nil {
			slog.LogAttrs(req.Context(), slog.LevelDebug, "an HTTP request's body could not be read again",
				slog.String("method", req.Method), slog.String("host", req.URL.Host), slog.Any("error", rewindErr))

			break
		}

		// What the attempt ended in: its error, or the status of a response,
		// which is given up here.
		status := release(resp)

		t.log(req, status, err, retry, wait)

		if stopped := sleep(req.Context(), wait); stopped != nil {
			// The body taken for an attempt that will not be made.
			if sent.Body != nil {
				_ = sent.Body.Close()
			}

			return nil, interrupted(stopped, status, err)
		}

		resp, err = t.base.RoundTrip(sent)
	}

	if resp != nil {
		// The caller gets its own request back, not a retry's copy.
		resp.Request = req
	}

	return resp, err //nolint:wrapcheck // the base's own error, unchanged
}

// release gives up a response, if there is one, and returns its status.
// Closed and not read: a read waits for what the server has yet to send, for
// as long as the server likes.
func release(resp *http.Response) int {
	if resp == nil {
		return 0
	}

	// Some transports give a response with no content a nil Body, which
	// net/http's client takes for an empty one.
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	return resp.StatusCode
}

// CloseIdleConnections forwards to base.
func (t *transport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// wait is how long to wait before sending req again after an attempt that
// ended in resp or err, and whether to send it again at all.
func (t *transport) wait(req *http.Request, resp *http.Response, err error, retry int) (time.Duration, bool) {
	var asked time.Duration

	switch {
	// A context that is done already: the answer in hand, whatever it is.
	case req.Context().Err() != nil:
		return 0, false
	case err != nil:
		if permanent(err) || !idempotent(req) && !unsent(err) {
			return 0, false
		}
	// No response and no error is a base that broke its contract: its
	// answer goes back as it is.
	case resp == nil || !idempotent(req) || !unavailable(resp.StatusCode):
		return 0, false
	default:
		var obeyed bool

		if asked, obeyed = retryAfter(resp.Header.Get("Retry-After"), t.maxBackoff); !obeyed {
			return 0, false
		}
	}

	// What was asked, and up to a quarter more: the clients a server sent
	// away together would otherwise come back together.
	const most = 1.25

	asked = t.between(float64(asked), most*float64(asked))

	wait := max(asked, t.backoffBefore(retry))

	// A wait the context's deadline would cut is not begun: the answer in
	// hand is worth more than the deadline's error at the end of it.
	if deadline, bounded := req.Context().Deadline(); bounded && time.Until(deadline) < wait {
		return 0, false
	}

	return wait, true
}

// backoffBefore is the wait before the given retry, the first being 1.
func (t *transport) backoffBefore(retry int) time.Duration {
	wait := min(t.backoff, t.maxBackoff)

	for range retry - 1 {
		// Compared before it is doubled: a wait near the largest duration
		// would double into a negative one.
		if wait >= t.maxBackoff/2 {
			wait = t.maxBackoff

			break
		}

		wait *= 2
	}

	const least, most = 0.75, 1.25

	return t.between(least*float64(wait), most*float64(wait))
}

// between is a wait drawn evenly from low to high, or to MaxBackoff when that
// is less. The bound comes before the draw: a draw cut at MaxBackoff
// afterwards leaves every wait that was past it exactly on it.
func (t *transport) between(low, high float64) time.Duration {
	high = min(high, float64(t.maxBackoff))

	drawn := low + (high-low)*rand.Float64() // #nosec G404 -- a jitter, not a secret

	// Compared before it is converted: past the largest duration the
	// conversion is not defined.
	if drawn >= float64(t.maxBackoff) {
		return t.maxBackoff
	}

	return time.Duration(drawn)
}

func (*transport) log(req *http.Request, status int, err error, retry int, wait time.Duration) {
	cause := slog.Int("status", status)

	if err != nil {
		// net/http's client words its errors with the whole URL: what is
		// inside is the cause, and the record has the host already. Every
		// one of the chain: a client's error may hold another client's.
		for {
			worded, found := errors.AsType[*url.Error](err)
			if !found {
				break
			}

			err = worded.Err
		}

		cause = slog.Any("error", err)
	}

	slog.LogAttrs(req.Context(), slog.LevelDebug, "retrying an HTTP request",
		slog.String("method", req.Method),
		slog.String("host", req.URL.Host),
		slog.Int("retry", retry),
		slog.Duration("wait", wait),
		cause,
	)
}

// rewindable reports a request that can be sent a second time: its body is
// none, or has a GetBody, and it has no Trailer. A caller fills the Trailer
// while the body is read, and the transport under this one may go on reading
// the body, and then the map, after its RoundTrip has returned: two attempts
// would have the one map between them. A Trailer that declares nothing
// counts: net/http sends what the map holds when the body ends.
func rewindable(req *http.Request) bool {
	return req.Trailer == nil && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil)
}

// rewound is a copy of req to send again, with its body from the start. A
// RoundTripper leaves the caller's request as it is.
func rewound(req *http.Request) (*http.Request, error) {
	sent := req.WithContext(req.Context())

	if req.Body == nil || req.Body == http.NoBody {
		return sent, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller's own function, and its error is only logged
	}

	sent.Body = body

	return sent, nil
}

// idempotent reports a request that sent twice does what it does sent once:
// a method RFC 9110 section 9.2.2 defines as such, or a request that says so
// itself with an idempotency key. The key's presence is what counts, as in
// net/http: one with no value marks the request and sends no header.
func idempotent(req *http.Request) bool {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	default:
		_, key := req.Header["Idempotency-Key"]
		_, legacy := req.Header["X-Idempotency-Key"]

		return key || legacy
	}
}

// unavailable reports a status that says the server could not answer now.
func unavailable(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// unsent reports an error that came before anything was sent: the connection
// could not be made.
func unsent(err error) bool {
	// Every OpError of the chain: through a proxy the dial's error is
	// inside another, whose Op is "proxyconnect".
	for {
		opErr, ok := errors.AsType[*net.OpError](err)

		switch {
		case !ok:
			return false
		case opErr.Op == "dial":
			return true
		}

		err = opErr.Err
	}
}

// permanent reports an error no further attempt changes.
func permanent(err error) bool {
	for _, refusal := range []error{xhttp.ErrOffline, xhttp.ErrCleartext, xhttp.ErrHandshakeRefused} {
		if errors.Is(err, refusal) {
			return true
		}
	}

	if _, untrusted := errors.AsType[*tls.CertificateVerificationError](err); untrusted {
		return true
	}

	unresolved, ok := errors.AsType[*net.DNSError](err)

	return ok && unresolved.IsNotFound
}

// retryAfter is the wait a Retry-After header asks for (RFC 9110 section
// 10.2.3: a number of seconds, or a date), and whether it is obeyed: one
// longer than limit is not. No header, one that is neither form and a date
// in the past ask for no wait.
func retryAfter(value string, limit time.Duration) (time.Duration, bool) {
	if value == "" {
		return 0, true
	}

	// Digits and nothing else: ParseInt alone also reads a sign.
	if !strings.ContainsFunc(value, func(char rune) bool { return char < '0' || char > '9' }) {
		// Compared in seconds: a number of them read from a header
		// overflows a duration. One too large for 64 bits is an error.
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds > int64(limit/time.Second) {
			return 0, false
		}

		return time.Duration(seconds) * time.Second, true
	}

	date, err := http.ParseTime(value)
	if err != nil {
		return 0, true
	}

	wait := time.Until(date)

	return max(wait, 0), wait <= limit
}

// sleep waits, or returns why the context ended first.
func sleep(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx) //nolint:wrapcheck // the context's own error, which the caller wraps
	}
}

// interrupted is the error of a request whose context ended while it waited
// to be sent again: the context's, and what the attempt before had ended in.
func interrupted(stopped error, status int, err error) error {
	if err != nil {
		return fmt.Errorf("%w, waiting to retry after: %w", stopped, err)
	}

	return fmt.Errorf("%w, waiting to retry after a %d", stopped, status)
}

package retry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/forkcloser/xhttp"
)

const (
	// DefaultBackoff is the wait before the first retry under Options that
	// name no Backoff.
	DefaultBackoff = 500 * time.Millisecond
	// DefaultMaxBackoff is the longest wait before a retry under Options
	// that name no MaxBackoff.
	DefaultMaxBackoff = 30 * time.Second
)

// drainLimit is how much of a response given up on is read before it is
// closed, so that its connection carries the retry. The body is the server's
// to size: past the limit the connection is given up with it.
const drainLimit = 64 << 10

// Options is what varies between retrying transports. The zero value sends
// each request once.
type Options struct {
	// Retries is how many times at most a request is sent again. Zero or
	// less sends each request once.
	Retries int
	// Backoff is the wait before the first retry. Zero or less is
	// DefaultBackoff.
	Backoff time.Duration
	// MaxBackoff is the longest wait before a retry, and the longest
	// Retry-After obeyed. Zero or less is DefaultMaxBackoff.
	MaxBackoff time.Duration
}

// NewTransport returns a transport that carries each request through base,
// and again as the package doc says. Its CloseIdleConnections forwards to
// base. It panics on a nil base.
func NewTransport(base http.RoundTripper, options Options) http.RoundTripper {
	if base == nil {
		panic("retry: NewTransport needs a transport to carry the attempts")
	}

	made := &transport{
		base:       base,
		retries:    options.Retries,
		backoff:    options.Backoff,
		maxBackoff: options.MaxBackoff,
	}

	if made.backoff <= 0 {
		made.backoff = DefaultBackoff
	}

	if made.maxBackoff <= 0 {
		made.maxBackoff = DefaultMaxBackoff
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
	resp, err := t.base.RoundTrip(req)

	// A request with no URL is the base's to refuse, once.
	if req.URL == nil || !rewindable(req) {
		return resp, err //nolint:wrapcheck // the base's own error, unchanged
	}

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
		status := 0
		if resp != nil {
			status = resp.StatusCode

			drain(resp.Body)
		}

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

	const least, spread = 0.75, 0.5

	jittered := float64(wait) * (least + spread*rand.Float64()) // #nosec G404 -- a jitter, not a secret

	// Compared before it is converted: past the largest duration the
	// conversion is not defined.
	if jittered >= float64(t.maxBackoff) {
		return t.maxBackoff
	}

	return time.Duration(jittered)
}

func (*transport) log(req *http.Request, status int, err error, retry int, wait time.Duration) {
	cause := slog.Any("error", err)
	if err == nil {
		cause = slog.Int("status", status)
	}

	slog.LogAttrs(req.Context(), slog.LevelDebug, "retrying an HTTP request",
		slog.String("method", req.Method),
		slog.String("host", req.URL.Host),
		slog.Int("retry", retry),
		slog.Duration("wait", wait),
		cause,
	)
}

// rewindable reports a request whose body can be sent a second time: it has
// none, or it has a GetBody.
func rewindable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// rewound is a copy of req to send again, with its body from the start. A
// RoundTripper leaves the caller's request as it is; not Request.Clone, which
// copies Trailer, which a caller fills while the body is read.
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
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// unsent reports an error that came before anything was sent: the connection
// could not be made.
func unsent(err error) bool {
	opErr, ok := errors.AsType[*net.OpError](err)

	return ok && opErr.Op == "dial"
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
// longer than limit is not. No header, one that is neither form, a negative
// number and a date in the past ask for no wait.
func retryAfter(value string, limit time.Duration) (time.Duration, bool) {
	if value == "" {
		return 0, true
	}

	// Compared in seconds: a number of them read from a header overflows a
	// duration, and one too large for 64 bits is read as the largest.
	switch seconds, err := strconv.ParseInt(value, 10, 64); {
	case err != nil && !errors.Is(err, strconv.ErrRange):
		// No number: a date, perhaps.
	case seconds < 0:
		return 0, true
	case seconds > int64(limit/time.Second):
		return 0, false
	default:
		return time.Duration(seconds) * time.Second, true
	}

	date, err := http.ParseTime(value)
	if err != nil {
		return 0, true
	}

	wait := time.Until(date)

	return max(wait, 0), wait <= limit
}

// drain reads what is left of a response given up on, within a limit, and
// closes it.
func drain(body io.ReadCloser) {
	_, _ = io.CopyN(io.Discard, body, drainLimit)
	_ = body.Close()
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

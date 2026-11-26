package retry_test

// The contract, from retry's docs, from net/http's for what a RoundTripper
// owes its caller (https://pkg.go.dev/net/http#RoundTripper), and from RFC
// 9110 for the idempotent methods (section 9.2.2) and Retry-After (section
// 10.2.3):
//   - a request is sent again, Retries times at most, when its attempt
//     failed or was answered 408 (RFC 9110, 15.5.9: the client "MAY repeat
//     that request"), 429, 500, 502, 503 or 504, and it is idempotent:
//     GET, HEAD, OPTIONS, TRACE, PUT, DELETE, or any method with an
//     Idempotency-Key or X-Idempotency-Key header, whatever its value;
//   - any other request is sent once, unless no connection could be made;
//   - a request whose body has no GetBody is sent once; a retry sends the
//     whole body again;
//   - nothing is sent again once the request's context is done, for a
//     certificate that is not trusted, for a host that does not resolve, or
//     for what xhttp refuses: ErrOffline, ErrCleartext, ErrHandshakeRefused;
//     nor a request with no URL or no header map (RoundTripper: "The
//     Request's URL and Header fields must be initialized");
//   - a request that is not sent again keeps the answer it has, as its
//     transport gave it: the response whatever the status, or the error
//     unchanged. That is when no retry is left, when Retry-After asks for
//     more than MaxBackoff, when the context is done already or its deadline
//     falls before the wait would end, and when GetBody fails;
//   - a response given up on to wait is closed and not read: what the
//     server has yet to send of it is not waited for. A context cancelled
//     during the wait ends it, and the error is the context's, holding the
//     attempt's error if it had one;
//   - the wait before a retry is drawn evenly between three quarters and
//     five quarters of Backoff doubled each time up to MaxBackoff, or to
//     MaxBackoff when that is less: no wait is longer, and they do not
//     gather on it. A Retry-After that asks for longer is obeyed (RFC 9110,
//     10.2.3: "how long the user agent ought to wait"), drawn evenly from
//     what it asks to a quarter more, or to MaxBackoff. It asks as a delay,
//     which is digits and nothing else (delay-seconds = 1*DIGIT), or as a
//     date; a value that is neither asks for nothing;
//   - a request that has a Trailer is sent once, and nothing of the Trailer
//     is read once the request is with the transport under this one: it is
//     filled as the body is read (net/http, Request.Trailer: "the map values can be
//     updated while the request body is read"), and a RoundTripper may read
//     the body, and close it, "in a separate goroutine even after RoundTrip
//     returns", so that two attempts would use the one map at once;
//   - the caller's request is left as it was, and is the response's Request;
//   - a retry is a debug record with the method, the host and the cause,
//     the status or the error, and no path and no query, those of a
//     *url.Error included (net/url: "Error reports an error and the
//     operation and URL that caused it");
//   - the zero Options sends each request once; a nil base panics, and so
//     does a negative Retries, Backoff or MaxBackoff.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/xhttp"
	"github.com/forkcloser/xhttp/retry"
)

var (
	// errFlaky is an error a further attempt may not meet.
	errFlaky = errors.New("the stand-in failed")
	// errBodyGone is the error of a GetBody that cannot give the body again.
	errBodyGone = errors.New("the body is gone")
)

// answer is what a scripted transport gives one attempt: an error, or a
// response of this status and header.
type answer struct {
	status int
	header http.Header
	err    error
}

// attempt is what a scripted transport was sent.
type attempt struct {
	method string
	body   string
	at     time.Time
}

// tracked is a response body that records its Close, and how often it was
// read.
type tracked struct {
	io.Reader

	closed atomic.Bool
	reads  atomic.Int32
}

func (b *tracked) Read(into []byte) (int, error) {
	b.reads.Add(1)

	return b.Reader.Read(into)
}

func (b *tracked) Close() error {
	b.closed.Store(true)

	return nil
}

// scripted is a transport that answers the attempts it is sent from a
// script, in order, then with 200, and records each attempt.
type scripted struct {
	mu      sync.Mutex
	script  []answer
	sent    []attempt
	bodies  []*tracked
	closeds int
}

func (s *scripted) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte

	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, attempt{method: req.Method, body: string(body), at: time.Now()})

	next := answer{status: http.StatusOK}
	if len(s.sent) <= len(s.script) {
		next = s.script[len(s.sent)-1]
	}

	if next.err != nil {
		return nil, next.err
	}

	header := next.header
	if header == nil {
		header = http.Header{}
	}

	content := &tracked{Reader: strings.NewReader("the answer's body")}
	s.bodies = append(s.bodies, content)

	return &http.Response{StatusCode: next.status, Header: header, Body: content, Request: req}, nil
}

func (s *scripted) CloseIdleConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeds++
}

func (s *scripted) attempts() []attempt {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]attempt(nil), s.sent...)
}

// failing is a script of the same answer, count times.
func failing(count int, with answer) []answer {
	script := make([]answer, count)
	for index := range script {
		script[index] = with
	}

	return script
}

// quick is Options that retry without making a test wait.
func quick(retries int) retry.Options {
	return retry.Options{Retries: retries, Backoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond}
}

// send carries one request of method through a retrying transport over
// base, and returns the status, or the error.
func send(
	t *testing.T,
	base http.RoundTripper,
	options retry.Options,
	method string,
	edit func(*http.Request),
) (int, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, "https://server.test/path?query=secret", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	if edit != nil {
		edit(req)
	}

	resp, err := retry.NewTransport(base, options).RoundTrip(req)
	if err != nil {
		return 0, err
	}

	_ = resp.Body.Close()

	return resp.StatusCode, nil
}

func TestAnIdempotentRequestIsSentAgain(t *testing.T) {
	t.Parallel()

	const retries = 3

	base := &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	status, err := send(t, base, quick(retries), http.MethodGet, nil)
	if err != nil || status != http.StatusOK || len(base.attempts()) != 3 {
		t.Errorf("two 503s then a 200: %d, %v after %d attempts; want 200 after 3", status, err, len(base.attempts()))
	}

	base = &scripted{script: failing(2, answer{err: errFlaky})}

	status, err = send(t, base, quick(retries), http.MethodGet, nil)
	if err != nil || status != http.StatusOK || len(base.attempts()) != 3 {
		t.Errorf(
			"two failures then a 200: %d, %v after %d attempts; want 200 after 3",
			status,
			err,
			len(base.attempts()),
		)
	}
}

// TestWhatComesBackIsTheLastAttempts: the response whatever its status, as
// a RoundTripper must, or the error itself; and every response given up on
// is closed and was never read, the last one left to the caller.
func TestWhatComesBackIsTheLastAttempts(t *testing.T) {
	t.Parallel()

	const retries = 2

	base := &scripted{script: failing(retries+1, answer{status: http.StatusBadGateway})}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://server.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := retry.NewTransport(base, quick(retries)).RoundTrip(req)
	if err != nil {
		t.Fatalf("a server that answers 502 every time = %v, want its response", err)
	}

	if resp.StatusCode != http.StatusBadGateway || len(base.attempts()) != retries+1 {
		t.Errorf("status %d after %d attempts; want 502 after %d", resp.StatusCode, len(base.attempts()), retries+1)
	}

	if resp.Request != req {
		t.Error("the response's Request is not the caller's")
	}

	for index, body := range base.bodies {
		if last := index == len(base.bodies)-1; body.closed.Load() == last {
			t.Errorf("the body of attempt %d: closed %t, want %t", index+1, !last, last)
		}

		if reads := body.reads.Load(); reads != 0 {
			t.Errorf("the body of attempt %d was read %d times before the caller had it", index+1, reads)
		}
	}

	content, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err != nil || string(content) != "the answer's body" {
		t.Errorf("the last response's body: %q, %v; want it whole", content, err)
	}

	base = &scripted{script: failing(retries+1, answer{err: errFlaky})}

	//nolint:err113,errorlint // the error itself is the contract, not one that wraps it
	if _, err = send(
		t,
		base,
		quick(retries),
		http.MethodGet,
		nil,
	); err != errFlaky ||
		len(base.attempts()) != retries+1 {
		t.Errorf("a base that fails every time = %v after %d attempts; want its own error after %d",
			err, len(base.attempts()), retries+1)
	}
}

func TestARequestThatIsNotIdempotentIsSentOnce(t *testing.T) {
	t.Parallel()

	base := &scripted{script: failing(1, answer{status: http.StatusServiceUnavailable})}

	status, err := send(t, base, quick(3), http.MethodPost, nil)
	if err != nil || status != http.StatusServiceUnavailable || len(base.attempts()) != 1 {
		t.Errorf(
			"a POST answered 503: %d, %v after %d attempts; want the 503 after 1",
			status,
			err,
			len(base.attempts()),
		)
	}

	base = &scripted{script: failing(1, answer{err: errFlaky})}

	//nolint:err113,errorlint // the error itself is the contract, not one that wraps it
	if _, err = send(t, base, quick(3), http.MethodPost, nil); err != errFlaky || len(base.attempts()) != 1 {
		t.Errorf("a POST that failed = %v after %d attempts; want its own error after 1", err, len(base.attempts()))
	}
}

// TestNoConnectionIsNothingSent: a request that is not idempotent is sent
// again when the connection could not be made, to the server or to the
// proxy before it.
func TestNoConnectionIsNothingSent(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := "http://" + listener.Addr().String()

	// Closed, so that nothing listens where the request goes.
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}

	nowhere, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}

	const retries = 2

	for what, sent := range map[string]struct {
		config  xhttp.Config
		address string
		op      string
	}{
		"a closed port":                   {xhttp.Config{Cleartext: true}, address, "dial"},
		"a proxy on a closed port":        {xhttp.Config{Cleartext: true, Proxy: http.ProxyURL(nowhere)}, "http://server.test/", "proxyconnect"},
		"https, a proxy on a closed port": {xhttp.Config{Cleartext: true, Proxy: http.ProxyURL(nowhere)}, "https://server.test/", "proxyconnect"},
	} {
		base := &counting{base: xhttp.NewTransport(sent.config)}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sent.address, strings.NewReader("content"))
		if err != nil {
			t.Fatal(err)
		}

		resp, err := retry.NewTransport(base, quick(retries)).RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}

		// The first OpError of the chain is the one net/http made.
		if refused, found := errors.AsType[*net.OpError](err); !found || refused.Op != sent.op {
			t.Fatalf("%s: %v, want a %s error", what, err, sent.op)
		}

		if base.count.Load() != retries+1 {
			t.Errorf("%s: a POST no connection carried was attempted %d times, want %d",
				what, base.count.Load(), retries+1)
		}
	}
}

// TestWhatCountsAsNoConnection: a dial's error anywhere under the errors
// net wraps it in, and no other error of the network.
func TestWhatCountsAsNoConnection(t *testing.T) {
	t.Parallel()

	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errFlaky}

	const retries = 2

	for what, failure := range map[string]struct {
		err      error
		attempts int
	}{
		"a dial":                       {dial, retries + 1},
		"a dial under a proxy's error": {&net.OpError{Op: "proxyconnect", Net: "tcp", Err: dial}, retries + 1},
		"the same, wrapped in between": {&net.OpError{Op: "proxyconnect", Err: fmt.Errorf("%w: wrapped", dial)}, retries + 1},
		"a read":                       {&net.OpError{Op: "read", Net: "tcp", Err: errFlaky}, 1},
		"a read under a proxy's error": {&net.OpError{Op: "proxyconnect", Err: &net.OpError{Op: "read", Err: errFlaky}}, 1},
		"a proxy's error with no dial": {&net.OpError{Op: "proxyconnect", Net: "tcp", Err: errFlaky}, 1},
		"an error that is not net's":   {errFlaky, 1},
		"a write":                      {&net.OpError{Op: "write", Net: "tcp", Err: errFlaky}, 1},
		"a dial under a read":          {&net.OpError{Op: "read", Net: "tcp", Err: dial}, retries + 1},
	} {
		base := &scripted{script: failing(retries+1, answer{err: failure.err})}

		if _, err := send(t, base, quick(retries), http.MethodPost, nil); !errors.Is(err, failure.err) ||
			len(base.attempts()) != failure.attempts {
			t.Errorf("%s: %v after %d attempts, want %d", what, err, len(base.attempts()), failure.attempts)
		}
	}
}

// counting counts the attempts a transport is sent.
type counting struct {
	base  http.RoundTripper
	count atomic.Int32
}

func (c *counting) RoundTrip(req *http.Request) (*http.Response, error) {
	c.count.Add(1)

	return c.base.RoundTrip(req)
}

// TestABodyIsSentAgainWhole: each attempt gets the body from its start, and
// a body that cannot be read again gets one attempt.
func TestABodyIsSentAgainWhole(t *testing.T) {
	t.Parallel()

	base := &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	status, err := send(t, base, quick(3), http.MethodPut, func(req *http.Request) {
		req.Body = io.NopCloser(strings.NewReader("content"))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("content")), nil }
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("a PUT with a GetBody: %d, %v; want 200", status, err)
	}

	for index, sent := range base.attempts() {
		if sent.body != "content" {
			t.Errorf("attempt %d was sent the body %q, want it whole", index+1, sent.body)
		}
	}

	if len(base.attempts()) != 3 {
		t.Errorf("a PUT with a GetBody was attempted %d times, want 3", len(base.attempts()))
	}

	base = &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	status, err = send(t, base, quick(3), http.MethodPut, func(req *http.Request) {
		req.Body = io.NopCloser(strings.NewReader("content"))
	})
	if err != nil || status != http.StatusServiceUnavailable || len(base.attempts()) != 1 {
		t.Errorf("a PUT of a stream: %d, %v after %d attempts; want the 503 after 1", status, err, len(base.attempts()))
	}

	// A body that cannot be read again after all: the answer in hand comes
	// back, whole.
	base = &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPut,
		"https://server.test/",
		strings.NewReader("content"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var asked int

	req.GetBody = func() (io.ReadCloser, error) {
		asked++

		return nil, errBodyGone
	}

	resp, err := retry.NewTransport(base, quick(3)).RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable || len(base.attempts()) != 1 {
		t.Fatalf(
			"a GetBody that fails = %v, %v after %d attempts; want the 503 after 1",
			resp,
			err,
			len(base.attempts()),
		)
	}

	if asked != 1 {
		t.Errorf("a GetBody that fails was asked %d times, want once: the answer in hand is kept", asked)
	}

	content, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err != nil || string(content) != "the answer's body" {
		t.Errorf("the 503's body: %q, %v; want it whole", content, err)
	}
}

// TestWhatNoAttemptChangesIsNotRetried: one attempt, and the error it ended in.
func TestWhatNoAttemptChangesIsNotRetried(t *testing.T) {
	t.Parallel()

	oldTLS := httptest.NewUnstartedServer(http.NotFoundHandler())
	oldTLS.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	oldTLS.StartTLS()
	t.Cleanup(oldTLS.Close)

	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(untrusted.Close)

	trusting := xhttp.Config{Roots: oldTLS.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}

	for name, permanent := range map[string]struct {
		base    http.RoundTripper
		address string
		matches func(error) bool
	}{
		"a host that does not resolve": {
			&scripted{script: failing(1, answer{err: &net.DNSError{Err: "no such host", IsNotFound: true}})},
			"https://server.test/",
			func(err error) bool { _, found := errors.AsType[*net.DNSError](err); return found },
		},
		"a certificate that is not trusted": {
			xhttp.NewTransport(xhttp.Config{}),
			untrusted.URL,
			func(err error) bool { _, found := errors.AsType[*tls.CertificateVerificationError](err); return found },
		},
		"a handshake the server refused": {
			xhttp.NewTransport(trusting),
			oldTLS.URL,
			func(err error) bool { return errors.Is(err, xhttp.ErrHandshakeRefused) },
		},
		"offline": {
			xhttp.NewTransport(xhttp.Config{Offline: true}),
			"https://server.test/",
			func(err error) bool { return errors.Is(err, xhttp.ErrOffline) },
		},
		"cleartext": {
			xhttp.NewTransport(xhttp.Config{}),
			"http://server.test/",
			func(err error) bool { return errors.Is(err, xhttp.ErrCleartext) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := &counting{base: permanent.base}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, permanent.address, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := retry.NewTransport(base, quick(3)).RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}

			if !permanent.matches(err) || base.count.Load() != 1 {
				t.Errorf("%v after %d attempts; want its own error after 1", err, base.count.Load())
			}
		})
	}
}

// TestALookupThatMayPassIsTriedAgain: of the errors of a lookup, only the
// one that says the host does not exist ends the attempts.
func TestALookupThatMayPassIsTriedAgain(t *testing.T) {
	t.Parallel()

	for what, lookup := range map[string]*net.DNSError{
		"a lookup that timed out":          {Err: "i/o timeout", Name: "server.test", IsTimeout: true},
		"a server that could not answer":   {Err: "server misbehaving", Name: "server.test", IsTemporary: true},
		"an error the resolver calls none": {Err: "lookup failed", Name: "server.test"},
	} {
		base := &scripted{script: failing(1, answer{err: lookup})}

		if status, err := send(t, base, quick(1), http.MethodGet, nil); err != nil || status != http.StatusOK ||
			len(base.attempts()) != 2 {
			t.Errorf("%s: %d, %v after %d attempts; want 200 after 2", what, status, err, len(base.attempts()))
		}
	}
}

// TestADoneContextIsNotRetried: an attempt that ended under a context that
// is done is the last, and its answer comes back; a deadline that leaves
// room ends nothing; a wait the deadline would cut is not begun, and the
// answer in hand comes back; a cancel during a wait ends the wait.
func TestADoneContextIsNotRetried(t *testing.T) {
	t.Parallel()

	// Cancelled as the attempt ends: the attempt's own answer, error or
	// response, and no wait.
	for name, script := range map[string][]answer{
		"an error": failing(4, answer{err: errFlaky}),
		"a 503":    failing(4, answer{status: http.StatusServiceUnavailable}),
	} {
		ctx, cancel := context.WithCancel(t.Context())

		base := &scripted{script: script}
		stopping := roundTripper(func(req *http.Request) (*http.Response, error) {
			defer cancel()

			return base.RoundTrip(req)
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://server.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := retry.NewTransport(stopping, quick(3)).RoundTrip(req)

		switch {
		case len(base.attempts()) != 1:
			t.Errorf("cancelled as the attempt ended in %s: %d attempts, want 1", name, len(base.attempts()))
		//nolint:err113,errorlint // the error itself is the contract, not one that wraps it
		case name == "an error" && err != errFlaky:
			t.Errorf("cancelled as the attempt ended in %s = %v, want its own error", name, err)
		case name == "a 503" && (err != nil || resp.StatusCode != http.StatusServiceUnavailable):
			t.Errorf("cancelled as the attempt ended in %s = %v, %v; want the 503", name, resp, err)
		}

		if resp != nil {
			_ = resp.Body.Close()
		}
	}

	// A deadline that leaves room for the waits ends nothing.
	roomy, enough := context.WithTimeout(t.Context(), time.Minute)
	defer enough()

	base := &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	req, err := http.NewRequestWithContext(roomy, http.MethodGet, "https://server.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := retry.NewTransport(base, quick(3)).RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK || len(base.attempts()) != 3 {
		t.Fatalf(
			"under a deadline a minute away: %v, %v after %d attempts; want 200 after 3",
			resp,
			err,
			len(base.attempts()),
		)
	}

	_ = resp.Body.Close()

	for name, script := range map[string][]answer{
		"after an error": failing(4, answer{err: errFlaky}),
		"after a 503":    failing(4, answer{status: http.StatusServiceUnavailable}),
	} {
		// A deadline that falls inside the wait: the wait is not begun, and
		// the answer in hand comes back at once.
		base = &scripted{script: script}

		bounded, stop := context.WithTimeout(t.Context(), 10*time.Second)

		req, err = http.NewRequestWithContext(bounded, http.MethodGet, "https://server.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		started := time.Now()
		minute := retry.Options{Retries: 3, Backoff: time.Minute, MaxBackoff: time.Minute}

		resp, err = retry.NewTransport(base, minute).RoundTrip(req)

		stop()

		switch {
		case len(base.attempts()) != 1 || time.Since(started) > 5*time.Second:
			t.Errorf("%s, a deadline inside the wait: %d attempts in %v; want 1, at once",
				name, len(base.attempts()), time.Since(started))
		//nolint:err113,errorlint // the error itself is the contract, not one that wraps it
		case name == "after an error" && err != errFlaky:
			t.Errorf("%s, a deadline inside the wait = %v, want the attempt's own error", name, err)
		case name == "after a 503" && (err != nil || resp.StatusCode != http.StatusServiceUnavailable):
			t.Errorf("%s, a deadline inside the wait = %v, %v; want the 503", name, resp, err)
		}

		if resp != nil {
			content, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if readErr != nil || string(content) != "the answer's body" {
				t.Errorf("%s, a deadline inside the wait: the body %q, %v; want it whole", name, content, readErr)
			}
		}

		// A cancel during the wait: the answer was given up to wait, and the
		// error is the context's, holding the attempt's error if it had one.
		base = &scripted{script: script}

		waiting, cancelWait := context.WithCancel(t.Context())
		timer := time.AfterFunc(50*time.Millisecond, cancelWait)

		rewinds := &tracked{Reader: strings.NewReader("content")}

		req, err = http.NewRequestWithContext(
			waiting,
			http.MethodPut,
			"https://server.test/",
			strings.NewReader("content"),
		)
		if err != nil {
			t.Fatal(err)
		}

		req.GetBody = func() (io.ReadCloser, error) { return rewinds, nil }

		started = time.Now()

		resp, err = retry.NewTransport(base, minute).RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}

		timer.Stop()
		cancelWait()

		if !errors.Is(err, context.Canceled) || len(base.attempts()) != 1 {
			t.Errorf("%s, a cancel during the wait = %v after %d attempts; want the context's error after 1",
				name, err, len(base.attempts()))
		}

		if name == "after an error" && !errors.Is(err, errFlaky) {
			t.Errorf("%s: %v does not hold the error of the attempt before", name, err)
		}

		if !rewinds.closed.Load() {
			t.Errorf("%s: the body taken for the retry that was not made was left open", name)
		}

		// A minute's backoff, cut at the cancel's 50 milliseconds.
		if waited := time.Since(started); waited > 30*time.Second {
			t.Errorf("%s: the wait went on %v past its context", name, waited)
		}
	}
}

// roundTripper makes a transport of a function.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestTheCallersRequestIsLeftAsItWas: a retry goes out on a copy.
func TestTheCallersRequestIsLeftAsItWas(t *testing.T) {
	t.Parallel()

	base := &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

	first := io.NopCloser(strings.NewReader("content"))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://server.test/", first)
	if err != nil {
		t.Fatal(err)
	}

	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("content")), nil }

	resp, err := retry.NewTransport(base, quick(3)).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	if len(base.attempts()) != 3 {
		t.Fatalf("attempted %d times, want 3", len(base.attempts()))
	}

	if req.Body != first {
		t.Error("the caller's request now has another body")
	}

	if len(req.Header) != 0 {
		t.Errorf("the caller's request now has the headers %v", req.Header)
	}

	if resp.Request != req {
		t.Error("the response's Request is not the caller's")
	}
}

// TestAResponseGivenUpOnIsNotWaitedFor: a server that answers 503 and then
// holds the rest of its body does not hold the caller. The transport under
// it is net/http's own, with no limit of its own on a body.
func TestAResponseGivenUpOnIsNotWaitedFor(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			return
		}

		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("try later. "))
		_ = http.NewResponseController(w).Flush()

		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	standard := &http.Transport{}
	t.Cleanup(standard.CloseIdleConnections)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	answered := make(chan error, 1)

	go func() {
		resp, err := retry.NewTransport(standard, quick(1)).RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("%w: status %d", errFlaky, resp.StatusCode)
			}
		}

		answered <- err
	}()

	select {
	case err := <-answered:
		if err != nil || requests.Load() != 2 {
			t.Errorf("%v after %d requests; want a 200 after 2", err, requests.Load())
		}
	// Far past what two requests to a local server take: the server holds
	// its body until the test ends.
	case <-time.After(30 * time.Second):
		t.Fatal("RoundTrip waits for the rest of a response it gave up on")
	}
}

func TestTheZeroOptionsSendOnce(t *testing.T) {
	t.Parallel()

	for name, options := range map[string]retry.Options{
		"the zero Options":       {},
		"no Retries, and a wait": {Backoff: time.Millisecond, MaxBackoff: time.Millisecond},
	} {
		base := &scripted{script: failing(2, answer{status: http.StatusServiceUnavailable})}

		status, err := send(t, base, options, http.MethodGet, nil)
		if err != nil || status != http.StatusServiceUnavailable || len(base.attempts()) != 1 {
			t.Errorf("%s: %d, %v after %d attempts; want the 503 after 1", name, status, err, len(base.attempts()))
		}
	}
}

// TestNewTransportRefusesANegativeOption: a count or a wait below zero is
// refused when the transport is made, and the smallest of each that is not
// is taken.
func TestNewTransportRefusesANegativeOption(t *testing.T) {
	t.Parallel()

	panics := func(options retry.Options) (panicked bool) {
		defer func() { panicked = recover() != nil }()

		retry.NewTransport(&scripted{}, options)

		return false
	}

	for name, options := range map[string]retry.Options{
		"a negative Retries":        {Retries: -1},
		"a negative Backoff":        {Retries: 1, Backoff: -1},
		"a negative MaxBackoff":     {Retries: 1, MaxBackoff: -1},
		"the most negative Retries": {Retries: math.MinInt},
		"the most negative Backoff": {Backoff: math.MinInt64},
	} {
		if !panics(options) {
			t.Errorf("%s: NewTransport did not panic", name)
		}
	}

	for name, options := range map[string]retry.Options{
		"zeros":                     {},
		"a nanosecond of each wait": {Retries: 1, Backoff: 1, MaxBackoff: 1},
		"the largest of each":       {Retries: math.MaxInt, Backoff: math.MaxInt64, MaxBackoff: math.MaxInt64},
	} {
		if panics(options) {
			t.Errorf("%s: NewTransport panicked", name)
		}
	}
}

func TestNewTransportNeedsABase(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("NewTransport with no base did not panic")
		}
	}()

	retry.NewTransport(nil, retry.Options{})
}

func TestCloseIdleConnectionsReachesTheBase(t *testing.T) {
	t.Parallel()

	base := &scripted{}

	(&http.Client{Transport: retry.NewTransport(base, retry.Options{})}).CloseIdleConnections()

	if base.closeds != 1 {
		t.Errorf("the base's CloseIdleConnections ran %d times, want 1", base.closeds)
	}

	// A base without the method is no fault.
	(&http.Client{Transport: retry.NewTransport(&counting{base: base}, retry.Options{})}).CloseIdleConnections()
}

// TestABaseThatAnswersNothing: no response and no error breaks the base's
// contract, and goes back as it came.
func TestABaseThatAnswersNothing(t *testing.T) {
	t.Parallel()

	var attempts int

	nothing := roundTripper(func(*http.Request) (*http.Response, error) {
		attempts++

		return nil, nil //nolint:nilnil // the broken base this test is about
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://server.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := retry.NewTransport(nothing, quick(3)).RoundTrip(req) //nolint:bodyclose // there is none
	if resp != nil || err != nil || attempts != 1 {
		t.Errorf("%v, %v after %d attempts; want nothing after 1", resp, err, attempts)
	}
}

// TestAResponseWithNoBody: a base may give a response a nil Body, which
// net/http's client takes for an empty one (https://go.dev/issue/38095). A
// retry gives such a response up as any other.
func TestAResponseWithNoBody(t *testing.T) {
	t.Parallel()

	var attempts int

	bodiless := roundTripper(func(req *http.Request) (*http.Response, error) {
		attempts++

		if attempts == 1 {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Request: req}, nil
		}

		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	})

	if status, err := send(t, bodiless, quick(1), http.MethodGet, nil); status != http.StatusOK || err != nil ||
		attempts != 2 {
		t.Errorf("%d, %v after %d attempts; want 200 after 2", status, err, attempts)
	}
}

// TestARequestNotInitializedIsRefusedOnce: a request with no URL, or no
// header map, is the transport's under it to refuse, and is given to it
// once.
func TestARequestNotInitializedIsRefusedOnce(t *testing.T) {
	t.Parallel()

	for what, edit := range map[string]func(*http.Request){
		"no URL":        func(req *http.Request) { req.URL = nil },
		"no header map": func(req *http.Request) { req.Header = nil },
	} {
		standard := &http.Transport{}
		t.Cleanup(standard.CloseIdleConnections)

		base := &counting{base: standard}

		if _, err := send(t, base, quick(3), http.MethodGet, edit); err == nil || base.count.Load() != 1 {
			t.Errorf(
				"a request with %s: %v after %d attempts, want net/http's error after 1",
				what,
				err,
				base.count.Load(),
			)
		}
	}
}

// records is a slog handler that keeps what it is given.
type records struct {
	mu   sync.Mutex
	kept []slog.Record
}

func (*records) Enabled(context.Context, slog.Level) bool { return true }

func (r *records) Handle(_ context.Context, record slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.kept = append(r.kept, record)

	return nil
}

func (r *records) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *records) WithGroup(string) slog.Handler      { return r }

// TestARetryIsLoggedWithoutThePath: one debug record for each retry, with
// the method, the host and the cause, and nothing of the path or the query,
// where a signed URL keeps its secret: not from the request, and not from an
// error net/http's client worded with the URL. The default logger is the
// process's, which is why this does not run in parallel.
func TestARetryIsLoggedWithoutThePath(t *testing.T) { //nolint:paralleltest // slog's default logger is process-wide
	previous := slog.Default()

	t.Cleanup(func() { slog.SetDefault(previous) })

	kept := &records{}
	slog.SetDefault(slog.New(kept))

	// As net/http's client words an error, alone and inside another.
	worded := &url.Error{Op: "Get", URL: "https://server.test/path?query=secret", Err: errFlaky}

	// A client's error that holds another client's, for another URL.
	issuer := &url.Error{Op: "Post", URL: "https://issuer.test/token?assertion=secret", Err: errFlaky}

	base := &scripted{script: []answer{
		{status: http.StatusServiceUnavailable},
		{err: errFlaky},
		{err: worded},
		{err: fmt.Errorf("fetching a token: %w", worded)},
		{err: &url.Error{Op: "Get", URL: worded.URL, Err: issuer}},
		{err: &url.Error{Op: "Get", URL: worded.URL, Err: fmt.Errorf("fetching a token: %w", issuer)}},
	}}

	causes := []string{
		"status=503", errFlaky.Error(), errFlaky.Error(), errFlaky.Error(), errFlaky.Error(), errFlaky.Error(),
	}

	if status, err := send(t, base, quick(len(causes)), http.MethodGet, nil); err != nil || status != http.StatusOK {
		t.Fatalf("%d, %v; want 200", status, err)
	}

	if len(kept.kept) != len(causes) {
		t.Fatalf("%d records for %d retries", len(kept.kept), len(causes))
	}

	for index, record := range kept.kept {
		var line strings.Builder

		line.WriteString(record.Message)
		record.Attrs(func(attr slog.Attr) bool {
			line.WriteString(" " + attr.String())

			return true
		})

		if record.Level != slog.LevelDebug {
			t.Errorf("%q is at level %v, want debug", line.String(), record.Level)
		}

		for _, want := range []string{"method=GET", "host=server.test", "retry=" + strconv.Itoa(index+1), causes[index]} {
			if !strings.Contains(line.String(), want) {
				t.Errorf("%q does not say %s", line.String(), want)
			}
		}

		for _, secret := range []string{"path", "query", "secret", "issuer", "assertion"} {
			if strings.Contains(line.String(), secret) {
				t.Errorf("%q holds %q, of the URL's path or query", line.String(), secret)
			}
		}
	}
}

// trailing is a request body that sets a trailer of its request when it has
// been read whole, as a caller that sends a checksum of what it streamed
// does. The value names the reading, so that one left by an earlier reading
// is told from this one's.
type trailing struct {
	io.Reader

	req     *http.Request
	reading int
}

func (b *trailing) Read(into []byte) (int, error) {
	read, err := b.Reader.Read(into)
	if errors.Is(err, io.EOF) {
		b.req.Trailer.Set("X-Checksum", "of reading "+strconv.Itoa(b.reading))
	}

	return read, err
}

func (*trailing) Close() error { return nil }

// TestARequestWithTrailersIsSentOnce: a request that declares trailers gets
// one attempt, whose answer comes back, and its trailer arrives as its body
// set it.
func TestARequestWithTrailersIsSentOnce(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		arrived []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		mu.Lock()
		defer mu.Unlock()

		arrived = append(arrived, r.Trailer.Get("X-Checksum"))

		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	// Declared before the request is sent, as net/http asks.
	req.Trailer = http.Header{"X-Checksum": nil}

	readings := 0
	body := func() (io.ReadCloser, error) {
		readings++

		return &trailing{Reader: strings.NewReader("content"), req: req, reading: readings}, nil
	}

	req.Body, _ = body()
	req.GetBody = body
	req.ContentLength = -1

	resp, err := retry.NewTransport(xhttp.NewTransport(xhttp.Config{Cleartext: true}), quick(3)).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if resp.StatusCode != http.StatusServiceUnavailable || len(arrived) != 1 || readings != 1 {
		t.Fatalf("status %d after %d attempts and %d bodies; want the 503 after 1 and 1",
			resp.StatusCode, len(arrived), readings)
	}

	if arrived[0] != "of reading 1" {
		t.Errorf("the server saw the trailer %q, want the one the body set", arrived[0])
	}
}

// eager is a request body that is read a few bytes at a time and sets a
// trailer of its request at each read, as a caller that sends a running
// checksum does.
type eager struct {
	req  *http.Request
	left int
}

func (b *eager) Read(into []byte) (int, error) {
	b.req.Trailer.Set("X-Checksum", "so far")

	if b.left == 0 {
		return 0, io.EOF
	}

	time.Sleep(time.Millisecond)

	read := min(len(into), b.left, 16)
	for index := range read {
		into[index] = 'x'
	}

	b.left -= read

	return read, nil
}

func (*eager) Close() error { return nil }

// TestTheTrailerIsNotReadOnceTheRequestIsSent: a server that answers before
// it has read the request leaves net/http's transport reading the body, and
// the body writing the Trailer, after RoundTrip has returned. Nothing here
// reads the Trailer then: the request gets its one attempt, and the race
// detector finds nothing.
func TestTheTrailerIsNotReadOnceTheRequestIsSent(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)

		// Before any of the body is read: the client is still sending it.
		control := http.NewResponseController(w)
		_ = control.EnableFullDuplex()

		w.WriteHeader(http.StatusServiceUnavailable)

		_ = control.Flush()
	}))
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Trailer = http.Header{"X-Checksum": nil}

	// 64 reads of a millisecond each: far longer than the answer takes.
	body := func() (io.ReadCloser, error) { return &eager{req: req, left: 1024}, nil }

	req.Body, _ = body()
	req.GetBody = body
	req.ContentLength = -1

	standard := &http.Transport{}
	t.Cleanup(standard.CloseIdleConnections)

	resp, err := retry.NewTransport(standard, quick(3)).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable || requests.Load() != 1 {
		t.Errorf("status %d after %d requests; want the 503 after 1", resp.StatusCode, requests.Load())
	}
}

// TestWhatMakesARequestOneThatIsSentOnce: of a PUT that is answered 503,
// what its body and its trailers make of it.
func TestWhatMakesARequestOneThatIsSentOnce(t *testing.T) {
	t.Parallel()

	for name, made := range map[string]struct {
		edit     func(*http.Request)
		attempts int
	}{
		"a body in memory":                {func(*http.Request) {}, 2},
		"no body":                         {func(req *http.Request) { req.Body, req.GetBody = nil, nil }, 2},
		"http.NoBody":                     {func(req *http.Request) { req.Body, req.GetBody = http.NoBody, nil }, 2},
		"a stream":                        {func(req *http.Request) { req.GetBody = nil }, 1},
		"trailers":                        {func(req *http.Request) { req.Trailer = http.Header{"X-Checksum": nil} }, 1},
		"trailers and no body":            {func(req *http.Request) { req.Body, req.Trailer = nil, http.Header{"X-Checksum": nil} }, 1},
		"a Trailer that declares nothing": {func(req *http.Request) { req.Trailer = http.Header{} }, 1},
	} {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodPut,
			"https://server.test/",
			strings.NewReader("content"),
		)
		if err != nil {
			t.Fatal(err)
		}

		made.edit(req)

		base := &scripted{script: failing(1, answer{status: http.StatusServiceUnavailable})}

		resp, err := retry.NewTransport(base, quick(1)).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if len(base.attempts()) != made.attempts {
			t.Errorf("%s: %d attempts, want %d", name, len(base.attempts()), made.attempts)
		}
	}
}

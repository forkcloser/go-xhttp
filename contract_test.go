package xhttp_test

// The contract, from xhttp's docs and from net/http's for what a RoundTripper
// owes its caller (https://pkg.go.dev/net/http#RoundTripper):
//   - the zero Config is the strictest posture, and each weaker one is asked
//     for by name: a request that is not https fails with ErrCleartext unless
//     Cleartext; a server with no post-quantum hybrid key exchange, or no TLS
//     1.3, fails the handshake with ErrHandshakeRefused unless the transport
//     names Classical or Legacy; a level there is none of panics when the
//     transport is made;
//   - Offline fails every request with ErrOffline, and nothing is dialed;
//   - a request the posture refuses has its body closed, as RoundTrip must;
//   - a read of a response body that waits longer than StallTimeout for a
//     byte fails with ErrStalled, over HTTP/1 and HTTP/2, and with neither
//     of the context's errors, since nothing of the caller's ended; an
//     error of that body afterwards is its own; the time between
//     two reads is not counted; a negative StallTimeout waits for ever; a
//     Close from another goroutine ends a read; the connection a protocol
//     switch hands over is not watched;
//   - the caller's request is left as it was, and is the response's Request;
//     a trailer the caller sets while the body is read is sent;
//   - UserAgent is the User-Agent of a request that has no such header;
//   - a Credential is made by NewCredential from a scheme that is an HTTP
//     token (RFC 9110, 5.6.2 and 11.1), a token that net/http sends as it
//     is in a header field (5.5: any octet but a control character other
//     than a tab, and nothing blank at an end), and one host or more, each written in ASCII as a URL writes it
//     (RFC 3986, 3.2.2: a name, an IPv4 address or an IPv6 address in
//     brackets, alone or with a port; no zone, which RFC 6874 writes one
//     way and net/url gives back another). Anything else is ErrCredential,
//     and the error does not hold the token;
//   - a credential goes with a request exactly when the request is https,
//     its URL writes its host in ASCII, and net/http dials for it the
//     address it dials for one of the credential's hosts over https: so not
//     to another host, a redirect's target included, and not in cleartext.
//     Of two credentials for a host the first is sent; a request's own
//     Authorization header is kept; the zero Credential is never sent;
//   - a request a client makes on a redirect (net/http: Request.Response is
//     "the redirect response which caused this request to be created") gets
//     the credential only when every request that led to it was https and
//     for a host the credential names; when that withholds the first
//     credential for a host, no other is sent;
//   - a Credential prints as its scheme and its hosts and never as its
//     token: under every verb of fmt, where fmt asks the value (fmt:
//     Formatter) and where it reads the fields itself (a value in an
//     unexported field), and so through log/slog and encoding/json;
//   - Redirects follows at most its limit, and none from https to anything
//     else: both are ErrRedirect;
//   - an error that is not the posture's is the standard library's, unchanged.
//
// That nothing reads or writes a global has no test: a read of
// http.DefaultTransport shows in nothing a caller can see.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/xhttp"
)

// secure is an https server whose TLS configure may narrow, and the roots
// that trust it.
func secure(t *testing.T, handler http.HandlerFunc, configure func(*tls.Config)) (*httptest.Server, *x509.CertPool) {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}

	if configure != nil {
		configure(server.TLS)
	}

	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	return server, roots
}

func ok(http.ResponseWriter, *http.Request) {}

// get makes one request and returns its status, or the error.
func get(ctx context.Context, t *testing.T, client *http.Client, address string) (int, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, nil
}

// closing is a request body that records its Close.
type closing struct {
	io.Reader

	closed atomic.Bool
}

func (c *closing) Close() error {
	c.closed.Store(true)

	return nil
}

func TestCleartextIsAskedFor(t *testing.T) {
	t.Parallel()

	var reached atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(server.Close)

	_, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{}), server.URL)
	if !errors.Is(err, xhttp.ErrCleartext) {
		t.Fatalf("the baseline over http = %v, want ErrCleartext", err)
	}

	if reached.Load() != 0 {
		t.Fatal("the baseline sent a request in cleartext")
	}

	status, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{Cleartext: true}), server.URL)
	if err != nil || status != http.StatusOK {
		t.Fatalf("Cleartext over http = %d, %v; want 200", status, err)
	}
}

func TestOffline(t *testing.T) {
	t.Parallel()

	var reached atomic.Int32

	server, roots := secure(t, func(http.ResponseWriter, *http.Request) { reached.Add(1) }, nil)

	client := xhttp.NewClient(xhttp.Config{Roots: roots, Offline: true})
	if _, err := get(t.Context(), t, client, server.URL); !errors.Is(err, xhttp.ErrOffline) {
		t.Fatalf("an offline request = %v, want ErrOffline", err)
	}

	if reached.Load() != 0 {
		t.Fatal("an offline transport reached the server")
	}
}

// TestARefusedRequestHasItsBodyClosed: RoundTrip closes the body on an error
// too, and a request the posture refuses never reaches the standard
// transport that would.
func TestARefusedRequestHasItsBodyClosed(t *testing.T) {
	t.Parallel()

	for name, refusal := range map[string]struct {
		config  xhttp.Config
		address string
		want    error
	}{
		"offline":   {xhttp.Config{Offline: true}, "https://offline.test/", xhttp.ErrOffline},
		"cleartext": {xhttp.Config{}, "http://cleartext.test/", xhttp.ErrCleartext},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := &closing{Reader: strings.NewReader("content")}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, refusal.address, body)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := xhttp.NewTransport(refusal.config).RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}

			if !errors.Is(err, refusal.want) {
				t.Fatalf("RoundTrip = %v, want %v", err, refusal.want)
			}

			if !body.closed.Load() {
				t.Fatal("the refused request's body was left open")
			}
		})
	}
}

func TestUnknownLevelPanics(t *testing.T) {
	t.Parallel()

	for _, level := range []xhttp.KeyExchange{-1, xhttp.Legacy + 1} {
		for name, build := range map[string]func(xhttp.Config){
			"NewTransport": func(config xhttp.Config) { xhttp.NewTransport(config) },
			"NewClient":    func(config xhttp.Config) { xhttp.NewClient(config) },
		} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("%s at level %d did not panic", name, level)
					}
				}()

				build(xhttp.Config{KeyExchange: level})
			}()
		}
	}
}

// TestARefusedHandshakeKeepsItsCause: ErrHandshakeRefused is added to the
// standard library's error, which stays reachable.
func TestARefusedHandshakeKeepsItsCause(t *testing.T) {
	t.Parallel()

	server, roots := secure(t, ok, func(config *tls.Config) { config.MaxVersion = tls.VersionTLS12 })

	_, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{Roots: roots}), server.URL)
	if !errors.Is(err, xhttp.ErrHandshakeRefused) {
		t.Fatalf("a TLS 1.2 server at the baseline = %v, want ErrHandshakeRefused", err)
	}

	if alert, found := errors.AsType[*net.OpError](err); !found || alert.Op != "remote error" {
		t.Fatalf("the server's alert is not in the chain of %v", err)
	}
}

// TestAnUntrustedServerIsTheStandardLibrarysError: an error the posture does
// not raise matches none of its sentinels.
func TestAnUntrustedServerIsTheStandardLibrarysError(t *testing.T) {
	t.Parallel()

	server, _ := secure(t, ok, nil)

	_, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{}), server.URL)

	if _, untrusted := errors.AsType[*tls.CertificateVerificationError](err); !untrusted {
		t.Fatalf("a server the roots do not trust = %v, want a certificate verification error", err)
	}

	for _, sentinel := range []error{
		xhttp.ErrOffline, xhttp.ErrCleartext, xhttp.ErrHandshakeRefused, xhttp.ErrStalled, xhttp.ErrRedirect,
	} {
		if errors.Is(err, sentinel) {
			t.Errorf("a certificate verification error matches %v", sentinel)
		}
	}
}

// stalling serves "/stops", a body that starts and never ends, and "/paused",
// one whose second half is sent when resume is.
func stalling(resume, release <-chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))

		_ = http.NewResponseController(w).Flush()

		if r.URL.Path == "/paused" {
			select {
			case <-resume:
				_, _ = w.Write([]byte("second"))
			case <-r.Context().Done():
			}

			return
		}

		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
}

// versions runs run once for each HTTP version, with what starts a server of
// that version and returns its address and the config that reaches it.
func versions(t *testing.T, run func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config))) {
	t.Helper()

	for name, major := range map[string]int{"HTTP/1": 1, "HTTP/2": 2} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			run(t, major, func(handler http.Handler) (string, xhttp.Config) {
				server := httptest.NewUnstartedServer(handler)
				config := xhttp.Config{}

				if major == 1 {
					server.Start()

					config.Cleartext = true
				} else {
					server.EnableHTTP2 = true
					server.StartTLS()

					config.Roots = x509.NewCertPool()
					config.Roots.AddCert(server.Certificate())
				}

				t.Cleanup(server.Close)

				return server.URL, config
			})
		})
	}
}

// open starts a request and returns its response, over the HTTP version asked.
func open(t *testing.T, client *http.Client, address string, major int) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.ProtoMajor != major {
		_ = resp.Body.Close()

		t.Fatalf("the response came over HTTP/%d, want HTTP/%d", resp.ProtoMajor, major)
	}

	return resp
}

// TestStalledBody: a body that stops arriving fails the read that waits for
// it, over HTTP/1 and HTTP/2; the time a caller takes between two reads is
// its own, and a body that goes on after it is read whole.
func TestStalledBody(t *testing.T) {
	t.Parallel()

	// Long enough that the second half, sent when the pause ends, arrives
	// well within it on a slow machine.
	const stall = 500 * time.Millisecond

	versions(t, func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		resume, release := make(chan struct{}, 1), make(chan struct{})

		address, config := serve(stalling(resume, release))

		// After serve: the server's Close waits for its handlers, so they
		// are released first.
		t.Cleanup(func() { close(release) })

		config.StallTimeout = stall
		client := xhttp.NewClient(config)

		stopped := open(t, client, address+"/stops", major)

		content, err := io.ReadAll(stopped.Body)

		if !errors.Is(err, xhttp.ErrStalled) || string(content) != "first" {
			t.Errorf("a body that stops: read %q, %v; want what arrived and ErrStalled", content, err)
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a body that stops: %v is also a context's error, and no context of the caller's ended", err)
		}

		if _, again := stopped.Body.Read(make([]byte, 1)); !errors.Is(again, xhttp.ErrStalled) ||
			errors.Is(again, context.Canceled) {
			t.Errorf("a second read of a stalled body: %v, want ErrStalled alone", again)
		}

		_ = stopped.Body.Close()

		if _, closed := stopped.Body.Read(make([]byte, 1)); closed == nil || errors.Is(closed, xhttp.ErrStalled) {
			t.Errorf("a read of a stalled body after its Close: %v, want the error of a closed body", closed)
		}

		paused := open(t, client, address+"/paused", major)

		first := make([]byte, len("first"))
		if _, err = io.ReadFull(paused.Body, first); err != nil {
			t.Fatal(err)
		}

		// Longer than the limit, and nobody is reading: not a stall.
		time.Sleep(3 * stall)

		resume <- struct{}{}

		rest, err := io.ReadAll(paused.Body)
		_ = paused.Body.Close()

		if err != nil || string(rest) != "second" {
			t.Errorf("after a pause between two reads: read %q, %v; want the rest of the body", rest, err)
		}
	})
}

// TestTheZeroConfigWatchesForAStall: the protection is on when nothing is
// said, at the minute the docs give. It takes that long to see.
func TestTheZeroConfigWatchesForAStall(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	server, roots := secure(t, stalling(nil, release), nil)

	t.Cleanup(func() { close(release) })

	resp := open(t, xhttp.NewClient(xhttp.Config{Roots: roots}), server.URL+"/stops", 1)
	started := time.Now()

	content, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if !errors.Is(err, xhttp.ErrStalled) || string(content) != "first" {
		t.Fatalf(
			"a body that stops, under the zero Config: read %q, %v; want what arrived and ErrStalled",
			content,
			err,
		)
	}

	// A timer never fires early; the first bytes may have come a moment
	// before the clock here started. It may fire late, by what a loaded
	// machine adds, and no later.
	if waited := time.Since(started); waited < time.Minute-time.Second || waited > time.Minute+15*time.Second {
		t.Errorf("the read failed after %v, want a minute", waited)
	}
}

// TestANegativeStallTimeoutWaitsForEver: a body that pauses is a stall under
// a limit shorter than the pause, and is read whole under a negative one.
func TestANegativeStallTimeoutWaitsForEver(t *testing.T) {
	t.Parallel()

	const pause = 300 * time.Millisecond

	pausing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))

		_ = http.NewResponseController(w).Flush()

		select {
		case <-time.After(pause):
			_, _ = w.Write([]byte("second"))
		case <-r.Context().Done():
		}
	})

	versions(t, func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		address, config := serve(pausing)

		config.StallTimeout = pause / 3
		limited := open(t, xhttp.NewClient(config), address, major)

		_, err := io.ReadAll(limited.Body)
		_ = limited.Body.Close()

		if !errors.Is(err, xhttp.ErrStalled) {
			t.Fatalf("under a limit shorter than the pause: %v, want ErrStalled", err)
		}

		config.StallTimeout = -1
		unlimited := open(t, xhttp.NewClient(config), address, major)

		content, err := io.ReadAll(unlimited.Body)
		_ = unlimited.Body.Close()

		if err != nil || string(content) != "firstsecond" {
			t.Errorf("with no limit: read %q, %v; want the whole body", content, err)
		}
	})
}

// TestCloseWhileReading: a Close from another goroutine ends a read that
// waits, which is how a caller gives up on one. The race detector is what
// judges it.
func TestCloseWhileReading(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	server := httptest.NewServer(stalling(nil, release))

	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	client := xhttp.NewClient(xhttp.Config{Cleartext: true})

	for range 20 {
		//nolint:bodyclose // closed below, under the goroutine that reads it
		resp := open(t, client, server.URL+"/stops", 1)
		done := make(chan error, 1)

		go func() {
			_, readErr := io.ReadAll(resp.Body)
			done <- readErr
		}()

		// Not a wait for the read to block: closing before, during or after
		// its first call are all the caller's right.
		time.Sleep(time.Millisecond)

		_ = resp.Body.Close()

		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("a read of a body that never ends, closed under it, ended without an error")
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Close did not end the read")
		}
	}
}

// TestAProtocolSwitchIsNotWatched: after a 101 the body is the connection,
// the caller's to read and write, and a quiet connection is not a stall.
func TestAProtocolSwitchIsNotWatched(t *testing.T) {
	t.Parallel()

	const stall = 100 * time.Millisecond

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)

			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = buffered.Flush()

		_, _ = io.Copy(conn, buffered)
	}))
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")

	resp, err := xhttp.NewClient(xhttp.Config{Cleartext: true, StallTimeout: stall}).Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	stream, switched := resp.Body.(io.ReadWriter)
	if resp.StatusCode != http.StatusSwitchingProtocols || !switched {
		t.Fatalf("status %d with a body of %T; want 101 and a connection to write to", resp.StatusCode, resp.Body)
	}

	back, done := make([]byte, len("echo")), make(chan error, 1)

	go func() {
		_, readErr := io.ReadFull(stream, back)
		done <- readErr
	}()

	// The read waits longer than the limit, with nothing arriving.
	time.Sleep(3 * stall)

	if _, err = stream.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}

	select {
	case err = <-done:
		if err != nil || string(back) != "echo" {
			t.Fatalf("a read across a quiet stretch: %q, %v; want what was written, echoed", back, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the echo never arrived")
	}
}

// TestTheCallersRequestIsLeftAsItWas: what the transport adds goes out on a
// copy, and the response names the caller's own request, whose context is
// still live once the body is closed.
func TestTheCallersRequestIsLeftAsItWas(t *testing.T) {
	t.Parallel()

	var agent atomic.Pointer[string]

	server, roots := secure(t, func(_ http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("User-Agent")
		agent.Store(&got)
	}, nil)

	bare := xhttp.NewTransport(xhttp.Config{Roots: roots, UserAgent: "contract/1"})

	for name, transport := range map[string]http.RoundTripper{
		"a transport": bare,
		"a transport with a credential": xhttp.Authorize(
			bare,
			credential(t, "Bearer", "token", strings.TrimPrefix(server.URL, "https://")),
		),
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if got := agent.Swap(nil); got == nil || *got != "contract/1" {
			t.Fatalf("%s: the server saw User-Agent %v, want the Config's", name, got)
		}

		if len(req.Header) != 0 {
			t.Errorf("%s: the caller's request now has the headers %v", name, req.Header)
		}

		if resp.Request != req {
			t.Errorf("%s: the response's Request is not the caller's", name)
		}

		if err = resp.Request.Context().Err(); err != nil {
			t.Errorf("%s: the context of the response's Request, once the body is closed: %v", name, err)
		}
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()

	var agent atomic.Pointer[string]

	server, roots := secure(t, func(_ http.ResponseWriter, r *http.Request) {
		got := strings.Join(r.Header.Values("User-Agent"), "|")
		agent.Store(&got)
	}, nil)

	named := xhttp.NewClient(xhttp.Config{Roots: roots, UserAgent: "contract/1"})
	unnamed := xhttp.NewClient(xhttp.Config{Roots: roots})

	for name, attempt := range map[string]struct {
		client *http.Client
		header []string
		want   string
	}{
		"the Config's, on a request with none": {named, nil, "contract/1"},
		"the request's own":                    {named, []string{"its-own/2"}, "its-own/2"},
		"none, when the request says so":       {named, []string{""}, ""},
		"Go's, under a Config with none":       {unnamed, nil, "Go-http-client/1.1"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		if attempt.header != nil {
			req.Header["User-Agent"] = attempt.header
		}

		resp, err := attempt.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if got := agent.Load(); got == nil || *got != attempt.want {
			t.Errorf("%s: the server saw %v, want %q", name, got, attempt.want)
		}
	}
}

// TestCredentialGoesToItsHostsOnly: the token reaches the host it names,
// and not the host a redirect leads to, a host it does not name, or a server
// in cleartext; nor the host it names when another host sent the client
// there. The redirects are net/http's own client's.
func TestCredentialGoesToItsHostsOnly(t *testing.T) {
	t.Parallel()

	const token = "Bearer for-the-first-host"

	var elsewhere, named, own atomic.Pointer[string]

	record := func(into *atomic.Pointer[string]) http.HandlerFunc {
		return func(_ http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("Authorization")
			into.Store(&got)
		}
	}

	var back atomic.Pointer[string]

	other, roots := secure(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/back" {
			http.Redirect(w, r, *back.Load()+"/chosen-elsewhere", http.StatusTemporaryRedirect)

			return
		}

		record(&elsewhere)(w, r)
	}, nil)

	first, _ := secure(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/asset", http.StatusFound)
		case "/again":
			http.Redirect(w, r, "/", http.StatusFound)
		case "/own":
			record(&own)(w, r)
		default:
			record(&named)(w, r)
		}
	}, nil)

	back.Store(&first.URL)

	plain := httptest.NewServer(record(&elsewhere))
	t.Cleanup(plain.Close)

	hostOf := func(address string) string {
		parsed, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}

		return parsed.Host
	}

	client := &http.Client{
		Transport: xhttp.Authorize(
			xhttp.NewTransport(xhttp.Config{Roots: roots, Cleartext: true}),
			credential(t, "Bearer", "for-the-first-host", hostOf(first.URL), hostOf(plain.URL)),
		),
	}

	expect := func(what string, got *atomic.Pointer[string], want string) {
		t.Helper()

		switch value := got.Swap(nil); {
		case value == nil:
			t.Errorf("%s: the server was not reached", what)
		case *value != want:
			t.Errorf("%s: Authorization %q, want %q", what, *value, want)
		}
	}

	for _, step := range []struct {
		what, address string
		got           *atomic.Pointer[string]
		want          string
	}{
		{"the named host", first.URL + "/", &named, token},
		{"a redirect to another host", first.URL + "/away", &elsewhere, ""},
		{"a host no credential names", other.URL, &elsewhere, ""},
		{"a redirect within the named host", first.URL + "/again", &named, token},
		{"the named host, on a redirect from a host that is not named", other.URL + "/back", &named, ""},
		{"a named host in cleartext", plain.URL, &elsewhere, ""},
	} {
		if _, err := get(t.Context(), t, client, step.address); err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}

		expect(step.what, step.got, step.want)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, first.URL+"/own", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Basic the-caller's")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	expect("a request with its own header", &own, "Basic the-caller's")
}

func TestRedirectsWithinHTTPSOnly(t *testing.T) {
	t.Parallel()

	plain := httptest.NewServer(http.HandlerFunc(ok))
	t.Cleanup(plain.Close)

	server, roots := secure(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		case "/once":
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}, nil)

	// Cleartext, so that the redirect is what refuses, not the transport.
	client := xhttp.NewClient(xhttp.Config{Roots: roots, Cleartext: true})

	if status, err := get(t.Context(), t, client, server.URL+"/once"); err != nil || status != http.StatusOK {
		t.Errorf("one redirect within https = %d, %v; want 200", status, err)
	}

	if _, err := get(t.Context(), t, client, server.URL+"/down"); !errors.Is(err, xhttp.ErrRedirect) {
		t.Errorf("a redirect from https to http = %v, want ErrRedirect", err)
	}
}

// trailing is a request body that sets a trailer of its request when it has
// been read whole, as a caller that sends a checksum of what it streamed does.
type trailing struct {
	io.Reader

	req *http.Request
}

func (b *trailing) Read(into []byte) (int, error) {
	read, err := b.Reader.Read(into)
	if errors.Is(err, io.EOF) {
		b.req.Trailer.Set("X-Checksum", "of the content")
	}

	return read, err
}

func (*trailing) Close() error { return nil }

// TestATrailerSetWhileTheBodyIsReadIsSent: a transport sends a copy of the
// request, and the copy must share the caller's trailers, which are not
// there yet when it is made.
func TestATrailerSetWhileTheBodyIsReadIsSent(t *testing.T) {
	t.Parallel()

	var arrived atomic.Pointer[string]

	server, roots := secure(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		got := r.Trailer.Get("X-Checksum")
		arrived.Store(&got)
	}, nil)

	bare := xhttp.NewTransport(xhttp.Config{Roots: roots, UserAgent: "contract/1"})

	for name, transport := range map[string]http.RoundTripper{
		"a transport": bare,
		"a transport with a credential": xhttp.Authorize(
			bare,
			credential(t, "Bearer", "token", strings.TrimPrefix(server.URL, "https://")),
		),
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		req.Body = &trailing{Reader: strings.NewReader("content"), req: req}
		req.ContentLength = -1
		req.Trailer = http.Header{"X-Checksum": nil}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if got := arrived.Swap(nil); got == nil || *got != "of the content" {
			t.Errorf("%s: the server saw the trailer %v, want the one set as the body ended", name, got)
		}
	}
}

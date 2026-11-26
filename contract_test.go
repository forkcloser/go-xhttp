package xhttp_test

// The contract, from xhttp's docs and from net/http's for what a RoundTripper
// owes its caller (https://pkg.go.dev/net/http#RoundTripper):
//   - the zero Config is the strictest posture, and each weaker one is asked
//     for by name: a request that is not https fails with ErrCleartext unless
//     Cleartext; a server with no post-quantum hybrid key exchange, or no TLS
//     1.3, fails the handshake with ErrHandshakeRefused unless the transport
//     names Classical or Legacy, whether it says so with an alert (RFC 8446,
//     4.1.1: "the server MUST abort the handshake with a handshake_failure
//     or an insufficient_security alert") or answers in TLS 1.2 and leaves
//     this side to end the handshake (appendix D.1: "If the server does not
//     support TLS 1.3, it will respond with a ServerHello containing an
//     older version number"); a level there is none of panics when the
//     transport is made;
//   - ErrHandshakeRefused is a handshake that failed for another reason than
//     the server's certificate or the network: not a certificate that is not
//     trusted, not a connection closed in the middle of the handshake, and
//     not what a server says once the handshake is done;
//   - Offline fails every request with ErrOffline, and nothing is dialed;
//   - a request the posture refuses has its body closed, as RoundTrip must;
//   - a request whose body the server stops taking for StallTimeout fails
//     with ErrStalled; so does one whose response has not begun that long
//     after it was sent, and a read of a response body that waits that long
//     for a byte; over HTTP/1 and HTTP/2, and with neither
//     of the context's errors, since nothing of the caller's ended; an
//     error of that body afterwards is its own; the caller's time is not
//     counted, in a read of the request's body or between two reads of the
//     response's; a negative StallTimeout waits for ever; a
//     Close from another goroutine ends a read; the connection a protocol
//     switch hands over is not watched;
//   - a response body read to its end holds nothing of the request any
//     more, closed or not, as under net/http's own transport (net/http,
//     Response.Body: "It is the caller's responsibility to close Body", and
//     its transport lets go of the request at the body's end all the same);
//   - the caller's request is left as it was, and is the response's Request;
//     a trailer the caller sets while the body is read is sent;
//   - UserAgent is the User-Agent of a request that has no such header, and
//     of the CONNECT net/http sends a proxy for a tunnel;
//   - a request's proxy is Config.Proxy's, or the environment's as net/http
//     reads it (http.ProxyFromEnvironment); a proxy whose URL holds
//     credentials is reached over https only, unless Cleartext: net/http
//     sends them as a Proxy-Authorization header (RFC 9110, 11.7.2) to an
//     http proxy, and as they are to a SOCKS5 one (RFC 1929), and the
//     request fails with ErrCleartext before anything is dialed;
//   - a Credential is made by NewCredential from a scheme that is an HTTP
//     token (RFC 9110, 5.6.2 and 11.1), a token that net/http sends as it
//     is in a header field (5.5: any octet but a control character other
//     than a tab, and nothing blank at an end), and one host or more, each
//     written in ASCII as a URL writes it (RFC 3986, 3.2.2: a name, an IPv4
//     address or an IPv6 address in brackets, alone or with a port; no zone,
//     which RFC 6874 writes one way and net/url gives back another).
//     Anything else is ErrCredential, and the error does not hold the token;
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
//   - no transport carries a request that a redirect leads to from https
//     to another scheme, whatever client follows it and whatever Cleartext
//     says (net/http, Request.Response: "the redirect response which caused
//     this request to be created"); a client from NewClient follows ten
//     redirects and no more; both are ErrRedirect;
//   - an error that is not the posture's is the standard library's, unchanged;
//   - a transport is safe for concurrent use (net/http: "A RoundTripper must
//     be safe for concurrent use by multiple goroutines").
//
// The pin's part of it is at the top of pin_test.go.
//
import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/go-xhttp"
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

	for _, level := range []xhttp.TLSLevel{-1, xhttp.Legacy + 1} {
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

				build(xhttp.Config{TLS: level})
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

// answeringInTLS12 is the address of a server that answers every ClientHello
// as a stack from before TLS 1.3 does: it knows nothing of the extension
// that offers TLS 1.3, reads the TLS 1.2 the hello also carries, and answers
// with a TLS 1.2 ServerHello. It sends no alert.
func answeringInTLS12(t *testing.T) string {
	t.Helper()

	return "https://" + answeringEachConnection(t, func(conn net.Conn) {
		// The record that carries the ClientHello: five bytes, the last
		// two its length.
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		if _, err := io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4])); err != nil {
			return
		}

		hello := []byte{0x03, 0x03} // TLS 1.2

		// The random, which is not the one a TLS 1.3 server signals a
		// downgrade with.
		for index := range 32 {
			hello = append(hello, byte(index+1))
		}

		hello = append(hello,
			0x00,       // no session
			0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0x00, // no compression
		)

		handshake := append([]byte{0x02, 0x00, 0x00, byte(len(hello))}, hello...)

		_, _ = conn.Write(append([]byte{0x16, 0x03, 0x03, 0x00, byte(len(handshake))}, handshake...))

		// Whatever the client answers, until it hangs up.
		_, _ = io.Copy(io.Discard, conn)
	})
}

// answeringEachConnection is the address of a listener that hands each
// connection it accepts to answer, and closes it after.
func answeringEachConnection(t *testing.T, answer func(net.Conn)) string {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

				answer(conn)
			}()
		}
	}()

	return listener.Addr().String()
}

// TestWhatARefusedHandshakeIs: a handshake that fails is ErrHandshakeRefused
// by where it failed and for what, and not by how the failure is typed.
func TestWhatARefusedHandshakeIs(t *testing.T) {
	t.Parallel()

	plain := httptest.NewServer(http.HandlerFunc(ok))
	t.Cleanup(plain.Close)

	untrusted := httptest.NewTLSServer(http.HandlerFunc(ok))
	t.Cleanup(untrusted.Close)

	// With TLS 1.3 a server turns a client down for its certificate once
	// the client's side of the handshake is done.
	demanding, demandingRoots := secure(
		t,
		ok,
		func(config *tls.Config) { config.ClientAuth = tls.RequireAnyClientCert },
	)

	// With the hello unread, which resets the connection, and with it read,
	// which ends it.
	resetting := "https://" + answeringEachConnection(t, func(conn net.Conn) {
		_, _ = conn.Read(make([]byte, 1))
	})
	ending := "https://" + answeringEachConnection(t, func(conn net.Conn) {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err == nil {
			_, _ = io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4]))
		}
	})

	// A context that ends when the server has the first byte of the
	// ClientHello, and never answers it: the middle of a handshake.
	inTheMiddle, leave := context.WithCancel(t.Context())
	defer leave()

	silent := "https://" + answeringEachConnection(t, func(conn net.Conn) {
		_, _ = conn.Read(make([]byte, 1))

		leave()

		_, _ = io.Copy(io.Discard, conn)
	})

	// A record of TLS 1.2 that is cut after three bytes, and one that is
	// whole and empty, which this side turns down with an alert of its own.
	answeringWith := func(record ...byte) string {
		return "https://" + answeringEachConnection(t, func(conn net.Conn) {
			header := make([]byte, 5)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}

			if _, err := io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4])); err != nil {
				return
			}

			_, _ = conn.Write(record)
		})
	}

	for name, server := range map[string]struct {
		ctx     context.Context //nolint:containedctx // one case of the table ends its own
		address string
		config  xhttp.Config
		refused bool
	}{
		"a server that answers in TLS 1.2, at HybridOnly": {
			t.Context(), answeringInTLS12(t), xhttp.Config{}, true,
		},
		"a server that answers in TLS 1.2, at Classical": {
			t.Context(), answeringInTLS12(t), xhttp.Config{TLS: xhttp.Classical}, true,
		},
		"a server that does not speak TLS": {
			t.Context(), "https://" + strings.TrimPrefix(plain.URL, "http://"), xhttp.Config{}, true,
		},
		"a server whose answer is a handshake record with nothing in it": {
			t.Context(), answeringWith(0x16, 0x03, 0x03, 0x00, 0x00), xhttp.Config{}, true,
		},
		"a server that ends the connection in the middle of its answer": {
			t.Context(), answeringWith(0x16, 0x03, 0x03), xhttp.Config{}, false,
		},
		"a server that resets the connection on the ClientHello": {t.Context(), resetting, xhttp.Config{}, false},
		"a server that ends the connection on the ClientHello":   {t.Context(), ending, xhttp.Config{}, false},
		"a context that ends in the middle of the handshake":     {inTheMiddle, silent, xhttp.Config{}, false},
		"a certificate that is not trusted":                      {t.Context(), untrusted.URL, xhttp.Config{}, false},
		"a server that wants a client certificate, in TLS 1.3": {
			t.Context(), demanding.URL, xhttp.Config{Roots: demandingRoots}, false,
		},
	} {
		_, err := get(server.ctx, t, xhttp.NewClient(server.config), server.address)
		if err == nil || errors.Is(err, xhttp.ErrHandshakeRefused) != server.refused {
			t.Errorf("%s: %v; ErrHandshakeRefused: %t, want %t", name, err, !server.refused, server.refused)
		}
	}
}

// TestAHandshakeTheServerNeverAnswers: the ten seconds a handshake is given
// end it with net/http's own error, a timeout, which is the network's and
// no refusal. It takes those ten seconds.
func TestAHandshakeTheServerNeverAnswers(t *testing.T) {
	t.Parallel()

	silent := "https://" + answeringEachConnection(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})

	started := time.Now()

	_, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{}), silent)

	timed, found := errors.AsType[net.Error](err)
	if !found || !timed.Timeout() || errors.Is(err, xhttp.ErrHandshakeRefused) {
		t.Errorf("%v, want a timeout that is no ErrHandshakeRefused", err)
	}

	if waited := time.Since(started); waited < 10*time.Second || waited > 25*time.Second {
		t.Errorf("the handshake was given %v, want ten seconds", waited)
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
		xhttp.ErrCredential, xhttp.ErrPin, xhttp.ErrPinMismatch,
	} {
		if errors.Is(err, sentinel) {
			t.Errorf("a certificate verification error matches %v", sentinel)
		}
	}
}

// patient is the StallTimeout of every test here that sets one. Each has a
// server that behaves beat it: an answer that begins, a body that goes on, a
// connection hung up on. That takes a millisecond on an idle machine, and
// hundreds of them on one that runs every other test at once under the race
// detector, so the limit is no shorter than this; a test waits it out once
// for each stall it provokes.
//
// What has to be longer than the limit is longer by half of it when it only
// has to be seen to outlast it (a timer never fires early), and by the whole
// of it when something else has to happen first.
const patient = 2 * time.Second

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

	versions(t, func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		resume, release := make(chan struct{}, 1), make(chan struct{})

		address, config := serve(stalling(resume, release))

		// After serve: the server's Close waits for its handlers, so they
		// are released first.
		t.Cleanup(func() { close(release) })

		config.StallTimeout = patient
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
		time.Sleep(patient + patient/2)

		resume <- struct{}{}

		rest, err := io.ReadAll(paused.Body)
		_ = paused.Body.Close()

		if err != nil || string(rest) != "second" {
			t.Errorf("after a pause between two reads: read %q, %v; want the rest of the body", rest, err)
		}
	})
}

// TestAResponseThatDoesNotBegin: a server that takes a request and says
// nothing fails it with ErrStalled once StallTimeout has passed, and with
// neither of the context's errors; under a negative StallTimeout it is
// waited for.
func TestAResponseThatDoesNotBegin(t *testing.T) {
	t.Parallel()

	versions(t, func(t *testing.T, _ int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		release := make(chan struct{})

		address, config := serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wait := release
			if r.URL.Path == "/late" {
				wait = nil
			}

			select {
			case <-wait:
			// The limit has to end the request first.
			case <-time.After(2 * patient):
				if wait == nil {
					_, _ = w.Write([]byte("content"))
				}
			case <-r.Context().Done():
			}
		}))

		t.Cleanup(func() { close(release) })

		config.StallTimeout = patient
		limited := xhttp.NewClient(config)

		// Far past the limit: what ends a request the limit did not.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		for _, path := range []string{"/never", "/late"} {
			started := time.Now()

			_, err := get(ctx, t, limited, address+path)
			if !errors.Is(err, xhttp.ErrStalled) || errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s: %v, want ErrStalled and no error of a context", path, err)
			}

			if err != nil && !strings.Contains(err.Error(), "no response began") {
				t.Errorf("%s: %v does not say the request was sent and not answered", path, err)
			}

			// A timer never fires early.
			if waited := time.Since(started); waited < patient {
				t.Errorf("%s: failed after %v, before the %v of the limit", path, waited, patient)
			}
		}

		config.StallTimeout = -1

		if status, err := get(t.Context(), t, xhttp.NewClient(config), address+"/late"); err != nil ||
			status != http.StatusOK {
			t.Errorf("with no limit, a response that begins late: %d, %v; want 200", status, err)
		}
	})
}

// lingering is a request body each of whose reads takes a while: one read,
// or as many as pieces says.
type lingering struct {
	wait   time.Duration
	pieces int
	given  int
}

func (b *lingering) Read(into []byte) (int, error) {
	if b.given >= max(b.pieces, 1) {
		return 0, io.EOF
	}

	time.Sleep(b.wait)

	b.given++

	return copy(into, "content"), nil
}

func (*lingering) Close() error { return nil }

// endless is a request body that never ends.
type endless struct{}

func (endless) Read(into []byte) (int, error) { return len(into), nil }

func (endless) Close() error { return nil }

// TestARequestTheServerStopsTaking: a server that reads none of a request's
// body fails the request with ErrStalled once StallTimeout has passed, and
// with neither of the context's errors. The time the caller's body takes to
// give its content is not the server's, and is not counted.
func TestARequestTheServerStopsTaking(t *testing.T) {
	t.Parallel()

	versions(t, func(t *testing.T, _ int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		release := make(chan struct{})

		address, config := serve(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/reads" {
				_, _ = io.Copy(io.Discard, r.Body)

				return
			}

			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))

		t.Cleanup(func() { close(release) })

		config.StallTimeout = patient
		transport := xhttp.NewTransport(config)

		// Far past the limit: what ends a request the limit did not.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		put := func(path string, body io.ReadCloser) (int, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, address+path, body)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := transport.RoundTrip(req)
			if err != nil {
				return 0, err
			}

			_ = resp.Body.Close()

			return resp.StatusCode, nil
		}

		started := time.Now()

		_, err := put("/deaf", endless{})
		if !errors.Is(err, xhttp.ErrStalled) || errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a body the server reads none of: %v, want ErrStalled and no error of a context", err)
		}

		if err != nil && !strings.Contains(err.Error(), "stopped taking the request") {
			t.Errorf("a body the server reads none of: %v does not say the request was not taken", err)
		}

		// A timer never fires early.
		if waited := time.Since(started); waited < patient {
			t.Errorf("a body the server reads none of: failed after %v, before the %v of the limit", waited, patient)
		}

		// Two reads, each longer than the limit: the second while the server
		// has had the first for longer than the limit.
		lingers := &lingering{wait: patient + patient/2, pieces: 2}

		if status, err := put("/reads", lingers); err != nil || status != http.StatusOK {
			t.Errorf("a body that takes its time, to a server that reads it: %d, %v; want 200", status, err)
		}
	})
}

// TestTheBodyNetHTTPTakesAgainIsReadThroughTheWaitToo: when a connection of
// its pool turns out closed, net/http sends the request a second time
// itself, with a body it takes from GetBody. That body's reads are still the
// caller's time: two, each longer than the limit, and the request is answered.
// The limit is what the first connection's hanging up, and net/http's taking
// another, have to beat.
func TestTheBodyNetHTTPTakesAgainIsReadThroughTheWaitToo(t *testing.T) {
	t.Parallel()

	var connections atomic.Int32

	// The first connection answers one request, reads the next whole and
	// hangs up on it; every other answers the request it is sent.
	address := "http://" + answeringEachConnection(t, func(conn net.Conn) {
		first := connections.Add(1) == 1
		reader := bufio.NewReader(conn)

		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

		if !first {
			return
		}

		if unanswered, err := http.ReadRequest(reader); err == nil {
			_, _ = io.Copy(io.Discard, unanswered.Body)
		}
	})

	transport := xhttp.NewTransport(xhttp.Config{Cleartext: true, StallTimeout: patient})

	// One request, so that the next travels on a connection of the pool.
	warm, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(warm)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPut,
		address,
		io.NopCloser(strings.NewReader("content")),
	)
	if err != nil {
		t.Fatal(err)
	}

	// What makes net/http send a PUT again by itself.
	req.Header.Set("Idempotency-Key", "one")
	req.ContentLength = -1

	taken := 0
	req.GetBody = func() (io.ReadCloser, error) {
		taken++

		return &lingering{wait: patient + patient/2, pieces: 2}, nil
	}

	resp, err = transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("%v after %d connections, the body taken again %d times; want 200", err, connections.Load(), taken)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || connections.Load() != 2 || taken != 1 {
		t.Errorf("status %d after %d connections, the body taken again %d times; want 200 after 2 and once",
			resp.StatusCode, connections.Load(), taken)
	}
}

// TestAnAnswerEndsTheWaitForIt: a server may answer before it has the whole
// request, and net/http then finishes sending the request on its own. The
// end of that sending starts no wait: the response is read to its end, past
// the limit, as long as it keeps arriving.
func TestAnAnswerEndsTheWaitForIt(t *testing.T) {
	t.Parallel()

	const pieces = 12

	versions(t, func(t *testing.T, _ int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		address, config := serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			control := http.NewResponseController(w)
			_ = control.EnableFullDuplex()

			// Before the request's body has come, and for twice the limit.
			for range pieces {
				_, _ = w.Write([]byte("piece "))
				_ = control.Flush()

				select {
				case <-time.After(patient / 6):
				case <-r.Context().Done():
					return
				}
			}
		}))

		config.StallTimeout = patient

		// The body is sent a third of the limit after the answer began.
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, address, &lingering{wait: patient / 3})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := xhttp.NewTransport(config).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		content, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if err != nil || string(content) != strings.Repeat("piece ", pieces) {
			t.Errorf("read %q, %v; want the %d pieces of the response", content, err, pieces)
		}
	})
}

// TestTheZeroConfigWatchesForAStall: the protection is on when nothing is
// said, at the minute the docs give, for a body that stops and for a
// response that never begins; and one that begins after 35 seconds is waited
// for, which no limit shorter than the minute would allow. It takes a minute
// to see, and the three run in that one minute.
func TestTheZeroConfigWatchesForAStall(t *testing.T) {
	t.Parallel()

	const late = 35 * time.Second

	release := make(chan struct{})
	stops := stalling(nil, release)

	server, roots := secure(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stops":
			stops(w, r)
		case "/late":
			select {
			case <-time.After(late):
				_, _ = w.Write([]byte("content"))
			case <-r.Context().Done():
			}
		default:
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}, nil)

	t.Cleanup(func() { close(release) })

	client := xhttp.NewClient(xhttp.Config{Roots: roots})

	// A timer never fires early; a clock here may start a moment after the
	// wait it measures. It may fire late, by what a loaded machine adds, and
	// no later.
	aMinute := func(what string, started time.Time) {
		t.Helper()

		if waited := time.Since(started); waited < time.Minute-time.Second || waited > time.Minute+15*time.Second {
			t.Errorf("%s failed after %v, want a minute", what, waited)
		}
	}

	// Not get, which ends the test from the goroutine it is called on.
	fetch := func(path string) (int, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, http.NoBody)
		if err != nil {
			return 0, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}

		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		return resp.StatusCode, err
	}

	stopped := open(t, client, server.URL+"/stops", 1)

	var group sync.WaitGroup

	group.Go(func() {
		started := time.Now()

		content, err := io.ReadAll(stopped.Body)
		_ = stopped.Body.Close()

		if !errors.Is(err, xhttp.ErrStalled) || string(content) != "first" {
			t.Errorf("a body that stops: read %q, %v; want what arrived and ErrStalled", content, err)
		}

		aMinute("the read of a body that stops", started)
	})

	group.Go(func() {
		started := time.Now()

		if _, err := fetch("/never"); !errors.Is(err, xhttp.ErrStalled) {
			t.Errorf("a response that never begins: %v, want ErrStalled", err)
		}

		aMinute("a request with no response", started)
	})

	group.Go(func() {
		if status, err := fetch("/late"); err != nil || status != http.StatusOK {
			t.Errorf("a response that begins after %v: %d, %v; want 200", late, status, err)
		}
	})

	group.Wait()
}

// TestANegativeStallTimeoutWaitsForEver: a body that pauses is a stall under
// a limit shorter than the pause, and is read whole under a negative one.
func TestANegativeStallTimeoutWaitsForEver(t *testing.T) {
	t.Parallel()

	// The limit has to end the read before the pause does.
	const pause = 2 * patient

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

		config.StallTimeout = patient
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

	resp, err := xhttp.NewClient(xhttp.Config{Cleartext: true, StallTimeout: patient}).Do(req)
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
	time.Sleep(patient + patient/2)

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

// TestNoRedirectLeavesHTTPS: every chain of up to three redirects between an
// https server and a cleartext one, under a transport that sends cleartext,
// through a client of the caller's own with no redirect policy, one that
// allows everything, and NewClient's. A chain is followed up to the first
// redirect that leads from https to cleartext, which is ErrRedirect, and the
// request it leads to is never sent.
func TestNoRedirectLeavesHTTPS(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		seen = map[string][]string{}
	)

	addresses := map[string]string{}

	// Each request names its chain and the schemes still to go through.
	handler := func(scheme string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			chain, left := r.URL.Query().Get("chain"), r.URL.Query().Get("left")

			mu.Lock()

			seen[chain] = append(seen[chain], scheme)
			mu.Unlock()

			if left == "" {
				return
			}

			next, rest, _ := strings.Cut(left, ",")

			http.Redirect(w, r, addresses[next]+"/?chain="+url.QueryEscape(chain)+"&left="+rest, http.StatusFound)
		}
	}

	secured, roots := secure(t, handler("https"), nil)

	plain := httptest.NewServer(handler("http"))
	t.Cleanup(plain.Close)

	addresses["https"], addresses["http"] = secured.URL, plain.URL

	config := xhttp.Config{Roots: roots, Cleartext: true}

	clients := map[string]*http.Client{
		"a client with no policy": {Transport: xhttp.NewTransport(config)},
		"a client that follows everything": {
			Transport:     xhttp.NewTransport(config),
			CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		},
		"NewClient": xhttp.NewClient(config),
	}

	var chains [][]string

	for _, first := range []string{"https", "http"} {
		chains = append(chains, []string{first})
	}

	for at := 0; at < len(chains); at++ {
		if len(chains[at]) > 3 {
			continue
		}

		for _, next := range []string{"https", "http"} {
			chains = append(chains, append(slices.Clone(chains[at]), next))
		}
	}

	for name, client := range clients {
		for _, chain := range chains {
			// What is sent: the chain up to its first step from https to
			// cleartext.
			sent, refused := chain, false

			for at := 1; at < len(chain); at++ {
				if chain[at-1] == "https" && chain[at] == "http" {
					sent, refused = chain[:at], true

					break
				}
			}

			id := name + ": " + strings.Join(chain, " to ")

			address := addresses[chain[0]] + "/?chain=" + url.QueryEscape(id) + "&left=" + strings.Join(chain[1:], ",")

			status, err := get(t.Context(), t, client, address)

			switch {
			case refused && !errors.Is(err, xhttp.ErrRedirect):
				t.Errorf("%s: %d, %v; want ErrRedirect", id, status, err)
			case !refused && (err != nil || status != http.StatusOK):
				t.Errorf("%s: %d, %v; want 200", id, status, err)
			}

			mu.Lock()

			if !slices.Equal(seen[id], sent) {
				t.Errorf("%s: the servers saw %v, want %v", id, seen[id], sent)
			}

			mu.Unlock()
		}
	}

	// Under a transport that sends no cleartext at all, it is still the
	// redirect that is refused.
	strict := &http.Client{Transport: xhttp.NewTransport(xhttp.Config{Roots: roots})}

	if _, err := get(
		t.Context(),
		t,
		strict,
		secured.URL+"/?chain=strict&left=http",
	); !errors.Is(
		err,
		xhttp.ErrRedirect,
	) {
		t.Errorf("with no cleartext allowed, https to http: %v, want ErrRedirect", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !slices.Equal(seen["strict"], []string{"https"}) {
		t.Errorf(
			"with no cleartext allowed, https to http: the servers saw %v, want the first request alone",
			seen["strict"],
		)
	}
}

// TestARedirectFromNowhereDoesNotLeaveHTTPS: a request made on a redirect
// whose response names no request, or a request with no URL, is taken to
// come from https, and is not carried to another scheme.
func TestARedirectFromNowhereDoesNotLeaveHTTPS(t *testing.T) {
	t.Parallel()

	var reached atomic.Int32

	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(plain.Close)

	transport := xhttp.NewTransport(xhttp.Config{Cleartext: true})

	for what, via := range map[string]*http.Response{
		"no request":            {StatusCode: http.StatusFound, Body: http.NoBody},
		"a request with no URL": {StatusCode: http.StatusFound, Body: http.NoBody, Request: &http.Request{}},
	} {
		body := &closing{Reader: strings.NewReader("content")}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, plain.URL, body)
		if err != nil {
			t.Fatal(err)
		}

		req.Response = via

		resp, err := transport.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}

		if !errors.Is(err, xhttp.ErrRedirect) || reached.Load() != 0 || !body.closed.Load() {
			t.Errorf(
				"a redirect with %s: %v, the server reached %d times, the body closed: %t; want ErrRedirect, none, and closed",
				what,
				err,
				reached.Load(),
				body.closed.Load(),
			)
		}
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

package xhttp_test

// Beside net/http: what the package does not change is held to what
// net/http's own transport does with the same request, on the same server.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/forkcloser/xhttp"
)

var (
	errBodyFails = errors.New("the request's body failed")
	// ephemeral is the address a connection of a test left from.
	ephemeral = regexp.MustCompile(`127\.0\.0\.1:\d+->`)
)

// TestARequestArrivesAsNetHTTPSendsIt: a request reaches the server through
// this transport as it does through net/http's, whatever its body: its
// method, its declared length, how it is framed, and what it carries.
func TestARequestArrivesAsNetHTTPSendsIt(t *testing.T) {
	t.Parallel()

	bodies := map[string]func() (io.Reader, bool){
		"no body":                   func() (io.Reader, bool) { return nil, false },
		"http.NoBody":               func() (io.Reader, bool) { return http.NoBody, false },
		"a body in memory":          func() (io.Reader, bool) { return strings.NewReader("content"), false },
		"an empty body in memory":   func() (io.Reader, bool) { return strings.NewReader(""), false },
		"a stream":                  func() (io.Reader, bool) { return io.MultiReader(strings.NewReader("content")), false },
		"a stream with nothing":     func() (io.Reader, bool) { return io.MultiReader(), false },
		"a body that is not asked":  func() (io.Reader, bool) { return strings.NewReader("content"), true },
		"a stream of several reads": func() (io.Reader, bool) { return &lingering{pieces: 3}, false },
	}

	versions(t, func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		var (
			mu   sync.Mutex
			seen []string
		)

		address, config := serve(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			content, err := io.ReadAll(r.Body)

			mu.Lock()
			defer mu.Unlock()

			seen = append(seen, fmt.Sprintf("HTTP/%d %s, length %d, encoding %v, expecting %q, body %q, %v",
				r.ProtoMajor, r.Method, r.ContentLength, r.TransferEncoding, r.Header.Get("Expect"), content, err))
		}))

		transports := []http.RoundTripper{
			&http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: config.Roots, MinVersion: tls.VersionTLS13},
				ForceAttemptHTTP2: true,
			},
			xhttp.NewTransport(config),
		}

		for name, body := range bodies {
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				seen = nil

				for _, transport := range transports {
					content, expecting := body()

					req, err := http.NewRequestWithContext(t.Context(), method, address, content)
					if err != nil {
						t.Fatal(err)
					}

					if expecting {
						req.Header.Set("Expect", "100-continue")
					}

					resp, err := transport.RoundTrip(req)
					if err != nil {
						t.Fatalf("%s, %s: %v", name, method, err)
					}

					_ = resp.Body.Close()

					if resp.ProtoMajor != major {
						t.Fatalf("%s, %s: answered over HTTP/%d, want HTTP/%d", name, method, resp.ProtoMajor, major)
					}
				}

				mu.Lock()

				if len(seen) != 2 || seen[0] != seen[1] {
					t.Errorf("%s, %s: the server saw, through net/http and through xhttp:\n%s", name, method,
						strings.Join(seen, "\n"))
				}

				mu.Unlock()
			}
		}

		for _, transport := range transports {
			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	})
}

// TestAnErrorThatIsNotThePackagesIsNetHTTPs: what fails for a reason the
// package has no name for fails as it does under net/http's own transport:
// the same error, of the same type, worded the same, and none of the
// package's sentinels in it.
func TestAnErrorThatIsNotThePackagesIsNetHTTPs(t *testing.T) {
	t.Parallel()

	untrusted := httptest.NewTLSServer(http.HandlerFunc(ok))
	t.Cleanup(untrusted.Close)

	refusing, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	nowhere := "http://" + refusing.Addr().String()

	if err = refusing.Close(); err != nil {
		t.Fatal(err)
	}

	answering := func(answer string) string {
		return "http://" + answeringEachConnection(t, func(conn net.Conn) {
			// The request's headers, to their end.
			reader := bufio.NewReader(conn)

			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}

			_, _ = conn.Write([]byte(answer))
		})
	}

	ended, cancel := context.WithCancel(t.Context())
	cancel()

	plain := httptest.NewServer(http.HandlerFunc(ok))
	t.Cleanup(plain.Close)

	for name, failing := range map[string]struct {
		ctx     context.Context //nolint:containedctx // one case of the table has ended
		address string
		edit    func(*http.Request)
	}{
		"a connection refused":               {t.Context(), nowhere, nil},
		"a certificate that is not trusted":  {t.Context(), untrusted.URL, nil},
		"a server that hangs up":             {t.Context(), answering(""), nil},
		"an answer that is not HTTP":         {t.Context(), answering("nonsense\r\n\r\n"), nil},
		"a length that is no number":         {t.Context(), answering("HTTP/1.1 200 OK\r\nContent-Length: some\r\n\r\n"), nil},
		"a body shorter than its length":     {t.Context(), answering("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"), nil},
		"a chunk that is no chunk":           {t.Context(), answering("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"), nil},
		"a context that has ended":           {ended, plain.URL, nil},
		"a header value with a line in it":   {t.Context(), plain.URL, func(req *http.Request) { req.Header.Set("X-Broken", "a\nb") }},
		"a header name that is no token":     {t.Context(), plain.URL, func(req *http.Request) { req.Header["a b"] = []string{"c"} }},
		"a method that is no token":          {t.Context(), plain.URL, func(req *http.Request) { req.Method = "GE T" }},
		"no host":                            {t.Context(), plain.URL, func(req *http.Request) { req.URL.Host = "" }},
		"a scheme the transport has none of": {t.Context(), plain.URL, func(req *http.Request) { req.URL.Scheme = "ftp" }},
		"no URL":                             {t.Context(), plain.URL, func(req *http.Request) { req.URL = nil }},
		"no header map":                      {t.Context(), plain.URL, func(req *http.Request) { req.Header = nil }},
		"a body that fails":                  {t.Context(), plain.URL, func(req *http.Request) { req.Body, req.ContentLength = io.NopCloser(iotest.ErrReader(errBodyFails)), 5 }},
	} {
		// Through net/http's, then through this package's.
		var seen [2]string

		for at, transport := range [2]http.RoundTripper{
			&http.Transport{},
			xhttp.NewTransport(xhttp.Config{Cleartext: true, TLS: xhttp.Legacy}),
		} {
			req, err := http.NewRequestWithContext(failing.ctx, http.MethodPut, failing.address, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}

			if failing.edit != nil {
				failing.edit(req)
			}

			resp, err := transport.RoundTrip(req)
			if err == nil {
				// The failure is in the body, then.
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if err == nil {
				t.Fatalf("%s: no error", name)
			}

			for _, sentinel := range []error{
				xhttp.ErrOffline, xhttp.ErrCleartext, xhttp.ErrHandshakeRefused, xhttp.ErrStalled, xhttp.ErrRedirect,
				xhttp.ErrCredential, xhttp.ErrPin, xhttp.ErrPinMismatch,
			} {
				if errors.Is(err, sentinel) {
					t.Errorf("%s: %v is the package's %v", name, err, sentinel)
				}
			}

			// The port a connection left from is its own.
			seen[at] = fmt.Sprintf("%T: %s", err, ephemeral.ReplaceAllString(err.Error(), "127.0.0.1:port->"))

			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}

		if seen[0] != seen[1] {
			t.Errorf("%s: through net/http and through xhttp:\n%s\n%s", name, seen[0], seen[1])
		}
	}
}

// TestOneTransportCarriesManyRequestsAtOnce: sixty-four requests at once
// through one transport, over each protocol, some answered whole, some
// stalled, some refused, each get what is theirs. The race detector reads
// the rest.
func TestOneTransportCarriesManyRequestsAtOnce(t *testing.T) {
	t.Parallel()

	const (
		callers = 64
		stall   = 200 * time.Millisecond
	)

	versions(t, func(t *testing.T, _ int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		release := make(chan struct{})
		stops := stalling(nil, release)

		address, config := serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/stops" {
				stops(w, r)

				return
			}

			_, _ = io.Copy(w, r.Body)
		}))

		t.Cleanup(func() { close(release) })

		config.StallTimeout = stall
		transport := xhttp.NewTransport(config)

		var group sync.WaitGroup

		for caller := range callers {
			group.Go(func() {
				name := fmt.Sprintf("caller %d", caller)

				path, body := "/echo", io.Reader(strings.NewReader(name))
				if caller%4 == 0 {
					path, body = "/stops", http.NoBody
				}

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, address+path, body)
				if err != nil {
					t.Error(err)

					return
				}

				resp, err := transport.RoundTrip(req)
				if err != nil {
					t.Errorf("%s: %v", name, err)

					return
				}

				content, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()

				switch {
				case resp.Request != req:
					t.Errorf("%s: the response is another request's", name)
				case path == "/stops" && (!errors.Is(err, xhttp.ErrStalled) || string(content) != "first"):
					t.Errorf("%s: read %q, %v; want what arrived and ErrStalled", name, content, err)
				case path == "/echo" && (err != nil || string(content) != name):
					t.Errorf("%s: read %q, %v; want its own request back", name, content, err)
				}
			})
		}

		group.Wait()
	})
}

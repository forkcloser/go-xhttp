package xhttp_test

// What a request leaves behind. The measure is exact: a context derived from
// one of a type the context package does not know registers with it, through
// its AfterFunc method, and takes the registration back when it ends. The
// request's context here is of such a type and counts what is registered.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/xhttp"
)

// errUnexpected is the error of a step of a test that did not go as planned.
var errUnexpected = errors.New("not what the test expects")

// counted is a context that counts the contexts derived from it that have
// not ended. It has no deadline and no value, and never ends itself.
type counted struct {
	never chan struct{}
	live  atomic.Int32
}

var _ context.Context = (*counted)(nil)

func counting() *counted {
	return &counted{never: make(chan struct{})}
}

func (*counted) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done is a channel that is never closed, and is not nil: the context
// package registers nothing with a parent that cannot end.
func (c *counted) Done() <-chan struct{} { return c.never }

func (*counted) Err() error { return nil }

func (*counted) Value(any) any { return nil }

// AfterFunc is what the context package calls to register a derived context.
func (c *counted) AfterFunc(func()) func() bool {
	c.live.Add(1)

	var once sync.Once

	return func() bool {
		once.Do(func() { c.live.Add(-1) })

		return true
	}
}

// settles waits for the count to come down to none, which a transport may
// reach a moment after a read returns, and returns what is left.
func (c *counted) settles() int32 {
	for deadline := time.Now().Add(10 * time.Second); c.live.Load() != 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}

	return c.live.Load()
}

// TestABodyReadToItsEndHoldsNothing: twenty responses read to their end and
// never closed leave no context of their requests behind, under net/http's
// own transport and under this one, watched or not, over both protocols;
// nor do twenty that are closed, read or not.
func TestABodyReadToItsEndHoldsNothing(t *testing.T) {
	t.Parallel()

	versions(t, func(t *testing.T, major int, serve func(http.Handler) (string, xhttp.Config)) {
		t.Helper()

		address, config := serve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("content"))
		}))

		unwatched := config
		unwatched.StallTimeout = -1

		uses := map[string]func(*http.Response) error{
			"read to its end and never closed": func(resp *http.Response) error {
				_, err := io.Copy(io.Discard, resp.Body)

				return err
			},
			"closed and never read": func(resp *http.Response) error { return resp.Body.Close() },
			"read to its end and closed": func(resp *http.Response) error {
				_, err := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()

				return err
			},
		}

		for name, transport := range map[string]http.RoundTripper{
			"net/http": &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: config.Roots, MinVersion: tls.VersionTLS13},
				ForceAttemptHTTP2: true,
			},
			"xhttp, watched":     xhttp.NewTransport(config),
			"xhttp, not watched": xhttp.NewTransport(unwatched),
		} {
			for use, body := range uses {
				parent := counting()

				for range 20 {
					req, err := http.NewRequestWithContext(parent, http.MethodGet, address, http.NoBody)
					if err != nil {
						t.Fatal(err)
					}

					resp, err := transport.RoundTrip(req) //nolint:bodyclose // some are left open: the test is of that
					if err != nil {
						t.Fatal(err)
					}

					if resp.ProtoMajor != major {
						t.Fatalf("%s: the response came over HTTP/%d, want HTTP/%d", name, resp.ProtoMajor, major)
					}

					if err = body(resp); err != nil {
						t.Fatalf("%s, %s: %v", name, use, err)
					}
				}

				if left := parent.settles(); left != 0 {
					t.Errorf("%s: of 20 responses %s, %d still hold a context of their request", name, use, left)
				}
			}

			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	})
}

// TestEveryWayOutLetsGoOfTheRequest: whatever a request ends in, an error
// before any response, a body that stalls, a connection handed over, nothing
// of it is held once the caller has done its part: read a body to an error,
// or closed it.
func TestEveryWayOutLetsGoOfTheRequest(t *testing.T) {
	t.Parallel()

	const (
		stall  = 50 * time.Millisecond
		rounds = 10
	)

	release := make(chan struct{})
	stops := stalling(nil, release)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/switch" {
			stops(w, r)

			return
		}

		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)

			return
		}

		defer func() { _ = conn.Close() }()

		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = buffered.Flush()

		// Until the client hangs up.
		_, _ = io.Copy(io.Discard, buffered)
	})

	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)

	two := httptest.NewUnstartedServer(handler)
	two.EnableHTTP2 = true
	two.StartTLS()
	t.Cleanup(two.Close)

	// After the servers: their Close waits for the handlers this releases.
	t.Cleanup(func() { close(release) })

	trusted := x509.NewCertPool()
	trusted.AddCert(two.Certificate())

	old, oldRoots := secure(t, ok, func(config *tls.Config) { config.MaxVersion = tls.VersionTLS12 })

	untrusted := httptest.NewTLSServer(http.HandlerFunc(ok))
	t.Cleanup(untrusted.Close)

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	nowhere := "http://" + listener.Addr().String()

	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}

	toAnother := xhttp.NewTransport(xhttp.Config{
		Pin: pinned(t, strings.TrimPrefix(untrusted.URL, "https://"), strings.Repeat("ab", sha256.Size)),
	})

	one := xhttp.NewTransport(xhttp.Config{Cleartext: true, StallTimeout: stall})
	second := xhttp.NewTransport(xhttp.Config{Roots: trusted, StallTimeout: stall})

	// What the caller does with a response. Each expects the stall.
	readToTheError := func(resp *http.Response) error {
		if _, err := io.Copy(io.Discard, resp.Body); !errors.Is(err, xhttp.ErrStalled) {
			return fmt.Errorf("%w: read %w, want ErrStalled", errUnexpected, err)
		}

		return nil
	}
	closeUnread := func(resp *http.Response) error { return resp.Body.Close() }
	closeTwiceAndRead := func(resp *http.Response) error {
		_ = resp.Body.Close()
		_ = resp.Body.Close()
		_, _ = resp.Body.Read(make([]byte, 1))

		return nil
	}

	for _, way := range []struct {
		name      string
		transport http.RoundTripper
		address   string
		// then is what the caller does with the response; nil when the
		// request is to fail before there is one.
		then func(*http.Response) error
	}{
		{"HTTP/1, a body that stalls, read to the error and left open", one, plain.URL + "/stops", readToTheError},
		{"HTTP/1, a body that stalls, closed unread", one, plain.URL + "/stops", closeUnread},
		{"HTTP/1, a body closed twice and read after", one, plain.URL + "/stops", closeTwiceAndRead},
		{"HTTP/1, a connection handed over, closed", one, plain.URL + "/switch", closeUnread},
		{"HTTP/2, a body that stalls, read to the error and left open", second, two.URL + "/stops", readToTheError},
		{"HTTP/2, a body that stalls, closed unread", second, two.URL + "/stops", closeUnread},
		{"HTTP/2, a body closed twice and read after", second, two.URL + "/stops", closeTwiceAndRead},
		{"a connection refused", one, nowhere, nil},
		{"a handshake refused", xhttp.NewTransport(xhttp.Config{Roots: oldRoots}), old.URL, nil},
		{"a certificate that is not trusted", xhttp.NewTransport(xhttp.Config{}), untrusted.URL, nil},
		{"offline", xhttp.NewTransport(xhttp.Config{Offline: true}), "https://server.test/", nil},
		{"cleartext refused", xhttp.NewTransport(xhttp.Config{}), "http://server.test/", nil},
		{"a certificate that is not the pinned one", toAnother, untrusted.URL, nil},
		{"a host that is not the pinned one", toAnother, "https://server.test/", nil},
	} {
		parent := counting()

		for range rounds {
			req, err := http.NewRequestWithContext(parent, http.MethodGet, way.address, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}

			if strings.HasSuffix(way.address, "/switch") {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "echo")
			}

			resp, err := way.transport.RoundTrip(req)

			switch {
			case way.then == nil && err == nil:
				_ = resp.Body.Close()

				t.Fatalf("%s: answered %d, want an error", way.name, resp.StatusCode)
			case way.then == nil:
			case err != nil:
				t.Fatalf("%s: %v", way.name, err)
			default:
				if err = way.then(resp); err != nil {
					t.Fatalf("%s: %v", way.name, err)
				}
			}
		}

		if left := parent.settles(); left != 0 {
			t.Errorf("%s: %d contexts of %d requests are still held", way.name, left, rounds)
		}
	}
}

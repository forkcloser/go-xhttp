package xhttp_test

// What a request leaves behind. The measure is exact: a context derived from
// one of a type the context package does not know registers with it, through
// its AfterFunc method, and takes the registration back when it ends. The
// request's context here is of such a type and counts what is registered.

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/xhttp"
)

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

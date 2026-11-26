package xhttp_test

// Beside net/http: what the package does not change is held to what
// net/http's own transport does with the same request, on the same server.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/forkcloser/xhttp"
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

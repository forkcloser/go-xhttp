package xhttp_test

// The proxy: which one a request takes, what it is sent, and what is kept
// from it. The stand-in here opens no tunnel: it keeps what it was asked and
// answers 502, which is all these tests need of it.

import (
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/forkcloser/xhttp"
)

var errNoProxy = errors.New("the stand-in picked no proxy")

// asked is what a proxy was sent.
type asked struct {
	method, target, agent, credentials string
}

// standIn is a proxy that tunnels nothing and keeps what it was asked.
type standIn struct {
	server *httptest.Server
	roots  *x509.CertPool

	mu   sync.Mutex
	seen []asked
}

// proxying starts a stand-in, reached in cleartext or over TLS.
func proxying(t *testing.T, secured bool) *standIn {
	t.Helper()

	proxy := &standIn{}

	proxy.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.mu.Lock()
		proxy.seen = append(proxy.seen, asked{
			method:      r.Method,
			target:      r.Host,
			agent:       r.Header.Get("User-Agent"),
			credentials: r.Header.Get("Proxy-Authorization"),
		})
		proxy.mu.Unlock()

		w.WriteHeader(http.StatusBadGateway)
	}))

	if secured {
		proxy.server.StartTLS()

		proxy.roots = x509.NewCertPool()
		proxy.roots.AddCert(proxy.server.Certificate())
	} else {
		proxy.server.Start()
	}

	t.Cleanup(proxy.server.Close)

	return proxy
}

// address is the stand-in's URL, with credentials or without.
func (p *standIn) address(t *testing.T, credentials *url.Userinfo) *url.URL {
	t.Helper()

	address, err := url.Parse(p.server.URL)
	if err != nil {
		t.Fatal(err)
	}

	address.User = credentials

	return address
}

// took returns what the stand-in was asked since the last call.
func (p *standIn) took() []asked {
	p.mu.Lock()
	defer p.mu.Unlock()

	seen := p.seen
	p.seen = nil

	return seen
}

// TestAProxysCredentialsTravelOverHTTPSOnly: a proxy whose URL holds
// credentials is not reached in cleartext, and the request fails with
// ErrCleartext before the proxy hears of it, unless the transport sends
// cleartext. One with no credentials is reached either way.
func TestAProxysCredentialsTravelOverHTTPSOnly(t *testing.T) {
	t.Parallel()

	const basic = "Basic dXNlcjpzZWNyZXQ=" // user:secret

	credentials := url.UserPassword("user", "secret")
	plain, secured := proxying(t, false), proxying(t, true)

	// A SOCKS5 proxy nothing listens at: it is refused, or it is dialed.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	socks := &url.URL{Scheme: "socks5", Host: listener.Addr().String()}

	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}

	withCredentials := *socks
	withCredentials.User = credentials

	for name, through := range map[string]struct {
		proxy     *standIn
		address   *url.URL
		cleartext bool
		refused   bool
		seen      []asked
	}{
		"an http proxy with credentials": {
			plain, plain.address(t, credentials), false, true, nil,
		},
		"an http proxy with a user and no password": {
			plain, plain.address(t, url.User("user")), false, true, nil,
		},
		"an http proxy with none": {
			plain, plain.address(t, nil), false, false, []asked{{http.MethodConnect, "server.test:443", "contract/1", ""}},
		},
		"an http proxy with credentials, under Cleartext": {
			plain, plain.address(t, credentials), true, false,
			[]asked{{http.MethodConnect, "server.test:443", "contract/1", basic}},
		},
		"an https proxy with credentials": {
			secured, secured.address(t, credentials), false, false,
			[]asked{{http.MethodConnect, "server.test:443", "contract/1", basic}},
		},
		"a SOCKS5 proxy with credentials":                  {nil, &withCredentials, false, true, nil},
		"a SOCKS5 proxy with none":                         {nil, socks, false, false, nil},
		"a SOCKS5 proxy with credentials, under Cleartext": {nil, &withCredentials, true, false, nil},
	} {
		config := xhttp.Config{
			Proxy:     http.ProxyURL(through.address),
			Cleartext: through.cleartext,
			UserAgent: "contract/1",
		}

		if through.proxy != nil {
			config.Roots = through.proxy.roots
		}

		// Never answered: the stand-in opens no tunnel, and nothing listens
		// at the SOCKS5 address.
		_, err := get(t.Context(), t, xhttp.NewClient(config), "https://server.test/")
		if err == nil || errors.Is(err, xhttp.ErrCleartext) != through.refused {
			t.Errorf("%s: %v; ErrCleartext: %t, want %t", name, err, !through.refused, through.refused)
		}

		if through.proxy == nil {
			continue
		}

		if seen := through.proxy.took(); len(seen) != len(through.seen) ||
			len(seen) == 1 && seen[0] != through.seen[0] {
			t.Errorf("%s: the proxy was asked %+v, want %+v", name, seen, through.seen)
		}
	}
}

// TestWhatPicksAProxyIsTheCallers: an error of Config.Proxy is the request's,
// unchanged, and a Proxy that picks none sends the request straight.
func TestWhatPicksAProxyIsTheCallers(t *testing.T) {
	t.Parallel()

	server, roots := secure(t, ok, nil)

	failing := xhttp.Config{
		Roots: roots,
		Proxy: func(*http.Request) (*url.URL, error) { return nil, errNoProxy },
	}

	if _, err := get(t.Context(), t, xhttp.NewClient(failing), server.URL); !errors.Is(err, errNoProxy) ||
		errors.Is(err, xhttp.ErrCleartext) {
		t.Errorf("a Proxy that fails: %v, want its own error", err)
	}

	direct := xhttp.Config{
		Roots: roots,
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }, //nolint:nilnil // no proxy and no error, as net/http reads it
	}

	if status, err := get(t.Context(), t, xhttp.NewClient(direct), server.URL); err != nil || status != http.StatusOK {
		t.Errorf("a Proxy that picks none: %d, %v; want 200", status, err)
	}
}

// TestTheTunnelRequestIsAsNetHTTPSendsIt: with no UserAgent named, the
// CONNECT a proxy is sent is the one net/http's own transport sends.
func TestTheTunnelRequestIsAsNetHTTPSendsIt(t *testing.T) {
	t.Parallel()

	proxy := proxying(t, false)

	for _, transport := range []http.RoundTripper{
		&http.Transport{Proxy: http.ProxyURL(proxy.address(t, nil))},
		xhttp.NewTransport(xhttp.Config{Proxy: http.ProxyURL(proxy.address(t, nil))}),
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://server.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := transport.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()

			t.Fatal("a proxy that opens no tunnel carried a request")
		}
	}

	if seen := proxy.took(); len(seen) != 2 || seen[0] != seen[1] {
		t.Errorf("the proxy was asked, through net/http and through xhttp: %+v", seen)
	}
}

// TestTheProxyIsTheEnvironments: a transport whose Config names no proxy
// takes the one the environment names. net/http reads the environment once
// for a process, so the request is made by this test binary run again, with
// an environment of its own.
func TestTheProxyIsTheEnvironments(t *testing.T) {
	t.Parallel()

	const target = "XHTTP_TEST_TARGET"

	if address := os.Getenv(target); address != "" {
		// The second run: the request is all it is for, and what it ends
		// in is the first run's to judge by what the proxy was asked.
		_, _ = get(t.Context(), t, xhttp.NewClient(xhttp.Config{UserAgent: "contract/1"}), address)

		return
	}

	proxy := proxying(t, false)

	again := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTheProxyIsTheEnvironments$")

	again.Env = append(os.Environ(),
		"HTTPS_PROXY="+proxy.server.URL, "https_proxy="+proxy.server.URL,
		"NO_PROXY=", "no_proxy=",
		target+"=https://server.test/",
	)

	if output, err := again.CombinedOutput(); err != nil {
		t.Fatalf("the second run: %v\n%s", err, output)
	}

	want := asked{http.MethodConnect, "server.test:443", "contract/1", ""}

	if seen := proxy.took(); len(seen) != 1 || seen[0] != want {
		t.Errorf("the proxy the environment names was asked %+v, want %+v", seen, want)
	}
}

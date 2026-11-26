package xhttp_test

// The walk within the bound: every level against a server of every offer;
// every form of host a credential names against every form of URL; a
// redirect limit at zero, at one and at the default, each at the limit and
// one past it.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/forkcloser/xhttp"
)

// TestKeyExchangeLevels: each server is reached by the levels that accept
// what it offers, and refused by the stricter ones.
func TestKeyExchangeLevels(t *testing.T) {
	t.Parallel()

	everyLevel := []xhttp.KeyExchange{xhttp.HybridOnly, xhttp.Classical, xhttp.Legacy}

	only := func(curve tls.CurveID) func(*tls.Config) {
		return func(config *tls.Config) { config.CurvePreferences = []tls.CurveID{curve} }
	}

	for name, offer := range map[string]struct {
		configure func(*tls.Config)
		reached   []xhttp.KeyExchange
	}{
		"Go's own offer":           {nil, everyLevel},
		"X25519MLKEM768 alone":     {only(tls.X25519MLKEM768), everyLevel},
		"SecP256r1MLKEM768 alone":  {only(tls.SecP256r1MLKEM768), everyLevel},
		"SecP384r1MLKEM1024 alone": {only(tls.SecP384r1MLKEM1024), everyLevel},
		"TLS 1.3, X25519 alone":    {only(tls.X25519), everyLevel[1:]},
		"TLS 1.3, P-256 alone":     {only(tls.CurveP256), everyLevel[1:]},
		"TLS 1.2 at most":          {func(config *tls.Config) { config.MaxVersion = tls.VersionTLS12 }, everyLevel[2:]},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server, roots := secure(t, ok, offer.configure)

			for _, level := range everyLevel {
				client := xhttp.NewClient(xhttp.Config{Roots: roots, KeyExchange: level})

				status, err := get(t.Context(), t, client, server.URL)

				switch {
				case slices.Contains(offer.reached, level) && (err != nil || status != http.StatusOK):
					t.Errorf("level %d = %d, %v; want 200", level, status, err)
				case !slices.Contains(offer.reached, level) && !errors.Is(err, xhttp.ErrHandshakeRefused):
					t.Errorf("level %d = %d, %v; want ErrHandshakeRefused", level, status, err)
				}
			}
		})
	}
}

// answering is a transport that answers every request itself.
type answering func(*http.Request)

func (f answering) RoundTrip(req *http.Request) (*http.Response, error) {
	f(req)

	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

// credential is NewCredential for arguments the test knows to be good.
func credential(t *testing.T, scheme, token string, hosts ...string) xhttp.Credential {
	t.Helper()

	made, err := xhttp.NewCredential(scheme, token, hosts...)
	if err != nil {
		t.Fatal(err)
	}

	return made
}

// carried reports whether a request for target, through a transport that
// has the credential, a Bearer one, goes out with its token.
func carried(t *testing.T, held xhttp.Credential, target *url.URL) bool {
	t.Helper()

	var sent string

	transport := xhttp.Authorize(
		answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
		held,
	)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://replaced.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	// The URL as it was parsed: one that net/url reads may not be one it
	// reads again once written.
	req.URL = target

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	switch sent {
	case "":
		return false
	case "Bearer token":
		return true
	default:
		t.Fatalf("%s: Authorization %q is neither the token nor nothing", target, sent)

		return false
	}
}

var errNotDialed = errors.New("the address is all the test wants")

type dialedKey struct{}

// standard is net/http's own transport, which dials nothing and tells the
// address it would have dialed.
//
//nolint:gochecknoglobals // one transport for every call: the fuzz target makes two a run
var standard = &http.Transport{
	Proxy: nil,
	DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		if into, ok := ctx.Value(dialedKey{}).(*string); ok {
			*into = address
		}

		return nil, errNotDialed
	},
}

// dialed is the address net/http dials for a request to target, as net
// reads it: an address and a port, or a name in lower case and a port. It
// is empty when net/http dials nothing for it.
func dialed(t *testing.T, target *url.URL) string {
	t.Helper()

	var address string

	req, err := http.NewRequestWithContext(
		context.WithValue(t.Context(), dialedKey{}, &address),
		http.MethodGet,
		"https://replaced.test/",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}

	req.URL = target

	resp, err := standard.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()

		t.Fatalf("%s: net/http answered a request it could not have sent", target)
	}

	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}

	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ""
	}

	if addr, err := netip.ParseAddr(name); err == nil {
		return netip.AddrPortFrom(addr, uint16(number)).String()
	}

	return net.JoinHostPort(strings.ToLower(name), strconv.FormatUint(number, 10))
}

// ascii reports whether text is ASCII.
func ascii(text string) bool {
	return !strings.ContainsFunc(text, func(char rune) bool { return char > unicode.MaxASCII })
}

// due is the contract's own answer: a credential for the host named goes
// with a request for target when target is https, writes its host in ASCII,
// and is dialed by net/http at the address it dials for the host named.
func due(t *testing.T, named string, target *url.URL) bool {
	t.Helper()

	address := dialed(t, target)

	return target.Scheme == "https" && ascii(target.Host) && address != "" &&
		address == dialed(t, &url.URL{Scheme: "https", Host: named})
}

// TestCredentialHostMatching: a credential is for the whole host name and
// the one port it names, and for nothing that looks like them. Each answer
// is held twice: to the table, and to the address net/http dials.
func TestCredentialHostMatching(t *testing.T) {
	t.Parallel()

	hosts := []string{
		"registry.test", "ported.test:8443", "[::1]:8443", "[::2]", "192.0.2.1", "default.test:443",
		"UPPER.test", "under_score.test", "xn--4xa.test", "[fe80::1]", "zeros.test:0443",
		"kernel.test",
	}

	held := credential(t, "Bearer", "token", hosts...)

	for address, want := range map[string]bool{
		"https://registry.test/":           true,
		"https://REGISTRY.TEST/":           true,
		"https://registry.test:443/":       true,
		"https://registry.test:0443/":      true,
		"https://registry.test:/":          true,
		"https://user@registry.test/":      true,
		"https://registry.test:8443/":      false,
		"https://registry.test:4430/":      false,
		"https://registry.test:65979/":     false,
		"https://notregistry.test/":        false,
		"https://sub.registry.test/":       false,
		"https://registry.test.evil.test/": false,
		"https://registry.tes/":            false,
		"https://registry.test./":          false,
		"http://registry.test/":            false,
		"http://registry.test:443/":        false,
		"https://ported.test:8443/":        true,
		"https://ported.test/":             false,
		"https://ported.test:443/":         false,
		"https://[::1]:8443/":              true,
		"https://[0:0:0:0:0:0:0:1]:8443/":  true,
		"https://[::1]/":                   false,
		"https://[::2]/":                   true,
		"https://[::2]:443/":               true,
		"https://[::2]:8443/":              false,
		"https://[::ffff:192.0.2.1]/":      false,
		"https://192.0.2.1/":               true,
		"https://192.0.2.10/":              false,
		"https://192.0.02.1/":              false,
		"https://192.0.2.1:8443/":          false,
		"https://default.test/":            true,
		"https://default.test:443/":        true,
		"https://upper.test/":              true,
		"https://under_score.test/":        true,
		"https://xn--4xa.test/":            true,
		"https://XN--4XA.test/":            true,
		"https://[fe80::1]/":               true,
		"https://[fe80::1%25en0]/":         false,
		"https://zeros.test/":              true,
		"https://unnamed.test/":            false,
		"https://kernel.test/":             true,
		// A host outside ASCII gets no credential, the one net/http dials
		// as a named host included: sigma for xn--4xa, the Kelvin sign
		// (U+212A) for k and the long s (U+017F) for s.
		"https://σ.test/":             false,
		"https://ς.test/":             false,
		"https://regi\u017ftry.test/": false,
		"https://\u212aernel.test/":   false,
	} {
		target, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}

		if got := carried(t, held, target); got != want {
			t.Errorf("%s: the token was sent: %t, want %t", address, got, want)
		}

		owed := slices.ContainsFunc(hosts, func(named string) bool { return due(t, named, target) })
		if owed != want {
			t.Errorf("%s: net/http's dialing makes it %t, the table says %t", address, owed, want)
		}
	}

	if carried(t, xhttp.Credential{}, &url.URL{Scheme: "https", Host: "registry.test"}) {
		t.Error("the zero Credential was sent")
	}
}

// TestNewCredentialRefuses: what could not be sent, or could never match,
// is ErrCredential when the credential is made, and the error does not hold
// the token.
func TestNewCredentialRefuses(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token"

	for what, args := range map[string]struct {
		scheme, token string
		hosts         []string
	}{
		"no scheme":                    {"", secret, []string{"registry.test"}},
		"a scheme of two words":        {"Bearer token", secret, []string{"registry.test"}},
		"a scheme with a colon":        {"Bearer:", secret, []string{"registry.test"}},
		"a scheme outside ASCII":       {"Beärer", secret, []string{"registry.test"}},
		"no token":                     {"Bearer", "", []string{"registry.test"}},
		"a token that ends a line":     {"Bearer", secret + "\n", []string{"registry.test"}},
		"a token with a line inside":   {"Bearer", secret + "\r\nHost: evil.test", []string{"registry.test"}},
		"a token with a NUL":           {"Bearer", secret + "\x00", []string{"registry.test"}},
		"a token with a DEL":           {"Bearer", secret + "\x7f", []string{"registry.test"}},
		"a token that starts in space": {"Bearer", " " + secret, []string{"registry.test"}},
		"a token that ends in space":   {"Bearer", secret + " ", []string{"registry.test"}},
		"a token that starts in a tab": {"Bearer", "\t" + secret, []string{"registry.test"}},
		"a token that ends in a tab":   {"Bearer", secret + "\t", []string{"registry.test"}},
		"a token that is one space":    {"Bearer", " ", []string{"registry.test"}},
		"no host":                      {"Bearer", secret, nil},
		"an empty host":                {"Bearer", secret, []string{""}},
		"one bad host of two":          {"Bearer", secret, []string{"registry.test", "https://registry.test"}},
		"a URL":                        {"Bearer", secret, []string{"https://registry.test"}},
		"a host and a slash":           {"Bearer", secret, []string{"registry.test/"}},
		"a host and a path":            {"Bearer", secret, []string{"registry.test/v2"}},
		"a wildcard":                   {"Bearer", secret, []string{"*.registry.test"}},
		"a space before":               {"Bearer", secret, []string{" registry.test"}},
		"a space after":                {"Bearer", secret, []string{"registry.test "}},
		"a user":                       {"Bearer", secret, []string{"user@registry.test"}},
		"a port that is a name":        {"Bearer", secret, []string{"registry.test:https"}},
		"a colon and no port":          {"Bearer", secret, []string{"registry.test:"}},
		"port zero":                    {"Bearer", secret, []string{"registry.test:0"}},
		"a port past the last":         {"Bearer", secret, []string{"registry.test:65536"}},
		"a signed port":                {"Bearer", secret, []string{"registry.test:+443"}},
		"a port and no host":           {"Bearer", secret, []string{":443"}},
		"a dot at the end":             {"Bearer", secret, []string{"registry.test."}},
		"a dot at the start":           {"Bearer", secret, []string{".registry.test"}},
		"two dots":                     {"Bearer", secret, []string{"registry..test"}},
		"a label of 64":                {"Bearer", secret, []string{strings.Repeat("a", 64) + ".test"}},
		"a name of 254":                {"Bearer", secret, []string{strings.Repeat("a.", 126) + "ab"}},
		"a name outside ASCII":         {"Bearer", secret, []string{"σ.test"}},
		"a name that is not UTF-8":     {"Bearer", secret, []string{"registry\xff.test"}},
		"IPv6 with no brackets":        {"Bearer", secret, []string{"::1"}},
		"IPv6 and a port, no brackets": {"Bearer", secret, []string{"::1:8443"}},
		"IPv4 in brackets":             {"Bearer", secret, []string{"[192.0.2.1]"}},
		"a name in brackets":           {"Bearer", secret, []string{"[registry.test]"}},
		"brackets twice":               {"Bearer", secret, []string{"[[::2]]"}},
		"an opening bracket alone":     {"Bearer", secret, []string{"[::2"}},
		"a closing bracket alone":      {"Bearer", secret, []string{"::2]"}},
		"a bracket before a name":      {"Bearer", secret, []string{"]registry.test"}},
		"a bracket after a name":       {"Bearer", secret, []string{"registry.test]"}},
		"brackets and no colon":        {"Bearer", secret, []string{"[::2]8443"}},
		"brackets and no port":         {"Bearer", secret, []string{"[::2]:"}},
		"nothing in brackets":          {"Bearer", secret, []string{"[]"}},
		"a zone":                       {"Bearer", secret, []string{"[fe80::1%en0]"}},
		"a zone as a URL writes it":    {"Bearer", secret, []string{"[fe80::1%25en0]"}},
		"a zone with a bracket":        {"Bearer", secret, []string{"[::%]]"}},
		"an empty zone":                {"Bearer", secret, []string{"[fe80::1%]"}},
	} {
		made, err := xhttp.NewCredential(args.scheme, args.token, args.hosts...)

		switch {
		case !errors.Is(err, xhttp.ErrCredential):
			t.Errorf("%s: %v, want ErrCredential", what, err)
		case strings.Contains(err.Error(), secret):
			t.Errorf("%s: the error holds the token: %v", what, err)
		case carried(t, made, &url.URL{Scheme: "https", Host: "registry.test"}):
			t.Errorf("%s: what came back with the error was sent", what)
		}
	}

	// At each limit, the last one that is taken.
	for what, host := range map[string]string{
		"a label of 63":   strings.Repeat("a", 63) + ".test",
		"a name of 253":   strings.Repeat("a.", 126) + "a",
		"the last port":   "registry.test:65535",
		"the first port":  "registry.test:1",
		"one label":       "localhost",
		"a hyphen":        "my-registry.test",
		"digits":          "0",
		"IPv6 and a port": "[2001:db8::1]:8443",
		"IPv4 and a port": "192.0.2.1:8443",
	} {
		if _, err := xhttp.NewCredential("Bearer", secret, host); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// TestATokenIsWhatAFieldCarries: for every octet, between two letters of a
// token, NewCredential takes the token exactly when net/http's own transport
// takes a request with it as its Authorization, and the token then goes out
// as it was given.
func TestATokenIsWhatAFieldCarries(t *testing.T) {
	t.Parallel()

	for octet := range 256 {
		token := "a" + string([]byte{byte(octet)}) + "b"

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Authorization", "Bearer "+token)

		// net/http refuses a header it will not write before it dials.
		resp, err := standard.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()

			t.Fatal("net/http answered a request it could not have sent")
		}

		taken := errors.Is(err, errNotDialed)

		held, err := xhttp.NewCredential("Bearer", token, "registry.test")
		if (err == nil) != taken {
			t.Errorf("octet %#02x: NewCredential: %v; net/http takes it: %t", octet, err, taken)

			continue
		}

		if err != nil {
			continue
		}

		var sent string

		transport := xhttp.Authorize(
			answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
			held,
		)

		req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err = transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if sent != "Bearer "+token {
			t.Errorf("octet %#02x: Authorization %q, want the token as it was given", octet, sent)
		}
	}
}

// TestCredentialSchemeAndToken: the Authorization is the scheme, a space and
// the token, as they were given.
func TestCredentialSchemeAndToken(t *testing.T) {
	t.Parallel()

	for _, given := range [][2]string{
		{"Bearer", "secret"},
		{"Basic", "dXNlcjpzZWNyZXQ="},
		{"token", "secret"},
		{"Digest", `username="user", realm="registry", response="6629fae4"`},
		{"!#$%&'*+-.^_`|~09azAZ", "~"},
	} {
		var sent string

		transport := xhttp.Authorize(
			answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
			credential(t, given[0], given[1], "registry.test"),
		)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.test/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if want := given[0] + " " + given[1]; sent != want {
			t.Errorf("Authorization %q, want %q", sent, want)
		}
	}
}

// TestTheFirstCredentialForAHostIsSent: of two credentials that name a host,
// the first, whatever the caller does afterwards with the slice it gave.
func TestTheFirstCredentialForAHostIsSent(t *testing.T) {
	t.Parallel()

	var sent string

	given := []xhttp.Credential{
		credential(t, "Bearer", "elsewhere", "other.test"),
		{},
		credential(t, "Bearer", "first", "registry.test"),
		credential(t, "Bearer", "second", "registry.test"),
	}

	transport := xhttp.Authorize(
		answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
		given...,
	)

	given[2] = given[3]

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()

	if sent != "Bearer first" {
		t.Errorf("Authorization %q, want the first credential that names the host", sent)
	}
}

func TestAuthorizeNeedsABase(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Authorize with no base did not panic")
		}
	}()

	xhttp.Authorize(nil)
}

// TestRedirectLimit: a client follows as many redirects as its limit, and
// refuses the one after.
func TestRedirectLimit(t *testing.T) {
	t.Parallel()

	server, roots := secure(t, func(w http.ResponseWriter, r *http.Request) {
		left, _ := strconv.Atoi(r.URL.Query().Get("left"))
		if left > 0 {
			http.Redirect(w, r, "/?left="+strconv.Itoa(left-1), http.StatusFound)
		}
	}, nil)

	transport := xhttp.NewTransport(xhttp.Config{Roots: roots})

	// ten is what a client from NewClient follows, by its docs.
	const ten = 10

	for _, limit := range []int{-1, 0, 1, ten} {
		client := &http.Client{Transport: transport, CheckRedirect: xhttp.Redirects(limit)}

		for hops := range max(limit, 0) + 2 {
			status, err := get(t.Context(), t, client, server.URL+"/?left="+strconv.Itoa(hops))

			switch {
			case hops <= limit && (err != nil || status != http.StatusOK):
				t.Errorf("limit %d, %d redirects = %d, %v; want 200", limit, hops, status, err)
			case hops > max(limit, 0) && !errors.Is(err, xhttp.ErrRedirect):
				t.Errorf("limit %d, %d redirects = %d, %v; want ErrRedirect", limit, hops, status, err)
			case hops == 0 && (err != nil || status != http.StatusOK):
				t.Errorf("limit %d, no redirect = %d, %v; want 200", limit, status, err)
			}
		}
	}

	byDefault := xhttp.NewClient(xhttp.Config{Roots: roots})

	atLimit := server.URL + "/?left=" + strconv.Itoa(ten)
	if status, err := get(t.Context(), t, byDefault, atLimit); err != nil || status != http.StatusOK {
		t.Errorf("NewClient, %d redirects = %d, %v; want 200", ten, status, err)
	}

	// One more, exactly: a client that followed eleven would pass a test of
	// a hundred.
	pastLimit := server.URL + "/?left=" + strconv.Itoa(ten+1)
	if _, err := get(t.Context(), t, byDefault, pastLimit); !errors.Is(err, xhttp.ErrRedirect) {
		t.Errorf("NewClient, %d redirects = %v, want ErrRedirect", ten+1, err)
	}
}

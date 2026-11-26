package xhttp_test

// The walk within the bound: every level against a server of every offer;
// every form of host a credential names against every form of URL; a
// redirect limit at zero, at one and at the default, each at the limit and
// one past it.

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"

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

// carried reports whether a request for target, through a transport that
// has a credential for hosts, goes out with the credential's token.
func carried(t *testing.T, hosts []string, target *url.URL) bool {
	t.Helper()

	var sent string

	transport := xhttp.Authorize(
		answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
		xhttp.Credential{Token: "token", Hosts: hosts},
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

// TestCredentialHostMatching: a credential is for the whole host name and
// the one port it names, and for nothing that looks like them.
func TestCredentialHostMatching(t *testing.T) {
	t.Parallel()

	hosts := []string{"registry.test", "ported.test:8443", "[::1]:8443", "[::2]", "192.0.2.1", "default.test:443"}

	for address, want := range map[string]bool{
		"https://registry.test/":           true,
		"https://REGISTRY.TEST/":           true,
		"https://registry.test:443/":       true,
		"https://user@registry.test/":      true,
		"https://registry.test:8443/":      false,
		"https://registry.test:4430/":      false,
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
		"https://[::1]/":                   false,
		"https://[::2]/":                   true,
		"https://[::2]:443/":               true,
		"https://[::2]:8443/":              false,
		"https://192.0.2.1/":               true,
		"https://192.0.2.10/":              false,
		"https://192.0.2.1:8443/":          false,
		"https://default.test/":            true,
		"https://default.test:443/":        true,
		"https://unnamed.test/":            false,
	} {
		target, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}

		if got := carried(t, hosts, target); got != want {
			t.Errorf("%s: the token was sent: %t, want %t", address, got, want)
		}
	}

	if carried(t, nil, &url.URL{Scheme: "https", Host: "registry.test"}) {
		t.Error("a credential that names no host was sent")
	}

	// A bracket that is not one of a pair is part of a name no host has.
	for _, stray := range []string{
		"]registry.test", "[registry.test", "registry.test]", "[[::2]]",
		// With one more character at the other end, which a cut of both ends would drop.
		"xregistry.test]", "[registry.testx", "x::2]", "[::2x",
	} {
		for _, address := range []string{"https://registry.test/", "https://[::2]/"} {
			target, err := url.Parse(address)
			if err != nil {
				t.Fatal(err)
			}

			if carried(t, []string{stray}, target) {
				t.Errorf("a credential for %q was sent to %s", stray, address)
			}
		}
	}
}

func TestCredentialScheme(t *testing.T) {
	t.Parallel()

	for scheme, want := range map[string]string{"": "Bearer secret", "Basic": "Basic secret", "token": "token secret"} {
		var sent string

		transport := xhttp.Authorize(
			answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
			xhttp.Credential{Scheme: scheme, Token: "secret", Hosts: []string{"registry.test"}},
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

		if sent != want {
			t.Errorf("scheme %q: Authorization %q, want %q", scheme, sent, want)
		}
	}
}

// TestTheFirstCredentialForAHostIsSent: of two credentials that name a host,
// the first with a token.
func TestTheFirstCredentialForAHostIsSent(t *testing.T) {
	t.Parallel()

	var sent string

	transport := xhttp.Authorize(
		answering(func(req *http.Request) { sent = req.Header.Get("Authorization") }),
		xhttp.Credential{Token: "elsewhere", Hosts: []string{"other.test"}},
		xhttp.Credential{Hosts: []string{"registry.test"}},
		xhttp.Credential{Token: "first", Hosts: []string{"registry.test"}},
		xhttp.Credential{Token: "second", Hosts: []string{"registry.test"}},
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

	if sent != "Bearer first" {
		t.Errorf("Authorization %q, want the first credential that names the host and has a token", sent)
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

	for _, limit := range []int{-1, 0, 1, xhttp.DefaultRedirects} {
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

	atLimit := server.URL + "/?left=" + strconv.Itoa(xhttp.DefaultRedirects)
	if status, err := get(t.Context(), t, byDefault, atLimit); err != nil || status != http.StatusOK {
		t.Errorf("NewClient, %d redirects = %d, %v; want 200", xhttp.DefaultRedirects, status, err)
	}

	if _, err := get(t.Context(), t, byDefault, atLimit+"1"); !errors.Is(err, xhttp.ErrRedirect) {
		t.Errorf("NewClient, past %d redirects = %v, want ErrRedirect", xhttp.DefaultRedirects, err)
	}
}

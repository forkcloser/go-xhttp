package xhttp_test

import (
	"net/url"
	"strings"
	"testing"
)

// portOf is the port a URL is for: the one it writes, or https's own.
func portOf(address *url.URL) string {
	if port := address.Port(); port != "" {
		return port
	}

	return "443"
}

// FuzzCredentialHost: a credential that names the host of one URL, as that
// URL writes it, is sent with a request for another URL exactly when the
// second is https, for the same host name whatever its case, on the same
// port. The truth is net/url's reading of both URLs; the package reads the
// host it is given by another road.
func FuzzCredentialHost(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://registry.test/", "https://registry.test/"},
		{"https://registry.test/", "https://REGISTRY.TEST:443/"},
		{"https://registry.test:443/", "https://registry.test/"},
		{"https://registry.test/", "https://registry.test:8443/"},
		{"https://registry.test/", "https://sub.registry.test/"},
		{"https://registry.test/", "https://registry.test.evil.test/"},
		{"https://registry.test/", "http://registry.test/"},
		{"https://registry.test/", "https://registry.test@evil.test/"},
		{"https://ported.test:8443/", "https://ported.test/"},
		{"https://[::1]:8443/", "https://[::1]:8443/"},
		{"https://[::1]/", "https://[::1]:443/"},
		{"https://[fe80::1%25en0]/", "https://[fe80::1%25en0]/"},
		{"https://192.0.2.1/", "https://192.0.2.10/"},
		{"https://registry.test/", "https://registry.test./"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, named, asked string) {
		host, err := url.Parse(named)
		if err != nil || host.Host == "" || host.Hostname() == "" {
			t.Skip("no host to name")
		}

		// A host is named as a name or as name:port: "name:" is neither.
		if strings.HasSuffix(host.Host, ":") {
			t.Skip("a host with a colon and no port")
		}

		target, err := url.Parse(asked)
		if err != nil || target.Host == "" || target.Scheme != "https" && target.Scheme != "http" {
			t.Skip("no request can be made for it")
		}

		want := target.Scheme == "https" &&
			strings.EqualFold(host.Hostname(), target.Hostname()) &&
			portOf(host) == portOf(target)

		if got := carried(t, []string{host.Host}, target); got != want {
			t.Fatalf(
				"a credential for %q, a request for %q: the token was sent: %t, want %t",
				host.Host,
				target,
				got,
				want,
			)
		}
	})
}

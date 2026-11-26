package xhttp_test

import (
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/forkcloser/go-xhttp"
)

// FuzzCredentialHost: a host is either refused when the credential is made,
// or its credential goes with a request exactly when the contract says so:
// the request is https, its URL writes its host in ASCII, and net/http dials
// for it the address it dials for the host named. The truth is the address
// net/http's own transport hands its dialer; the package reads both hosts
// by another road.
func FuzzCredentialHost(f *testing.F) {
	for _, seed := range [][2]string{
		{"registry.test", "https://registry.test/"},
		{"registry.test", "https://REGISTRY.TEST:443/"},
		{"registry.test:443", "https://registry.test/"},
		{"registry.test:0443", "https://registry.test:00443/"},
		{"registry.test", "https://registry.test:8443/"},
		{"registry.test", "https://sub.registry.test/"},
		{"registry.test", "https://registry.test.evil.test/"},
		{"registry.test", "http://registry.test/"},
		{"registry.test", "https://registry.test@evil.test/"},
		{"registry.test", "https://registry.test./"},
		{"registry.test", "https://regi\u017ftry.test/"},
		{"kernel.test", "https://Kernel.test/"},
		{"kernel.test", "https://\u212aernel.test/"},
		{"xn--4xa.test", "https://σ.test/"},
		{"xn--4xa.test", "https://ς.test/"},
		{"σ.test", "https://σ.test/"},
		{"ported.test:8443", "https://ported.test/"},
		{"[::1]:8443", "https://[::1]:8443/"},
		{"[::1]", "https://[0:0:0:0:0:0:0:1]:443/"},
		{"[fe80::1%en0]", "https://[fe80::1%25en0]/"},
		{"[::ffff:192.0.2.1]", "https://192.0.2.1/"},
		{"192.0.2.1", "https://192.0.2.10/"},
		{"192.0.2.1", "https://192.0.02.1/"},
		{"192.0.02.1", "https://192.0.02.1/"},
		{"0", "https://0/"},
		{"]0", "https://0/"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, named, asked string) {
		held, err := xhttp.NewCredential("Bearer", "token", named)
		if err != nil {
			if !errors.Is(err, xhttp.ErrCredential) {
				t.Fatalf("a credential for %q: %v, which is not ErrCredential", named, err)
			}

			t.Skip("not a host a credential names")
		}

		target, err := url.Parse(asked)
		if err != nil || target.Host == "" || target.Scheme != "https" && target.Scheme != "http" {
			t.Skip("no request can be made for it")
		}

		if dialed(t, &url.URL{Scheme: "https", Host: named}) == "" {
			t.Fatalf("a credential was made for %q, which net/http dials nothing for", named)
		}

		if got, want := carried(t, held, target), due(t, named, target); got != want {
			t.Fatalf(
				"a credential for %q, a request for %q: the token was sent: %t, want %t",
				named,
				target,
				got,
				want,
			)
		}
	})
}

// FuzzPinFingerprint: whatever is written for a fingerprint, NewPin takes it
// exactly when it is one of the two forms, and the pin is then of the bytes
// those digits spell. The truth is a regular expression and encoding/hex.
func FuzzPinFingerprint(f *testing.F) {
	const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, seed := range []string{
		fingerprint, strings.ToUpper(fingerprint), asOpenSSLPrints(fingerprint), "", fingerprint[1:], fingerprint + "0",
		strings.Repeat("0", 95), strings.Repeat(":", 95), "sha256:" + fingerprint, fingerprint + "\n",
		strings.ReplaceAll(asOpenSSLPrints(fingerprint), ":", "-"), asOpenSSLPrints(fingerprint) + ":",
	} {
		f.Add(seed)
	}

	forms := regexp.MustCompile(`^([0-9a-fA-F]{64}|([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})$`)

	f.Fuzz(func(t *testing.T, written string) {
		pin, err := xhttp.NewPin("device.test", written)

		if !forms.MatchString(written) {
			if !errors.Is(err, xhttp.ErrPin) {
				t.Fatalf("%q is no fingerprint, and NewPin gave %v, %v", written, pin, err)
			}

			return
		}

		spelled, _ := hex.DecodeString(strings.ReplaceAll(written, ":", ""))

		if want := "device.test:443 pinned to " + hex.EncodeToString(spelled); err != nil || pin.String() != want {
			t.Fatalf("%q is a fingerprint, and NewPin gave %v, %v; want %s", written, pin, err, want)
		}
	})
}

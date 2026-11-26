package xhttp_test

// The pin's contract, from xhttp's docs and from crypto/tls's for what a
// client can hold a server to (https://pkg.go.dev/crypto/tls#Config):
//   - a Pin is made by NewPin from a host, written as a credential's is, and
//     the SHA-256 of a certificate in hexadecimal: 64 digits, or 32 pairs
//     with a colon between two, as `openssl x509 -fingerprint -sha256`
//     prints it. Anything else is ErrPin;
//   - a transport that has a Pin completes a handshake exactly when the
//     first certificate the server presents (crypto/tls,
//     ConnectionState.PeerCertificates: "The first element is the leaf
//     certificate that the connection is verified against") has that
//     SHA-256, over its DER encoding. Who signed it, what name it bears and
//     whether it is in date are not consulted. Another certificate is
//     ErrPinMismatch, which is neither ErrHandshakeRefused nor a
//     certificate that is not trusted, holds the fingerprint presented, and
//     comes before anything of the request is sent (crypto/tls,
//     VerifyConnection: "If it returns a non-nil error, the handshake is
//     aborted");
//   - a server that presents the pinned certificate and does not hold its
//     key completes no handshake either, and hears nothing of the request:
//     crypto/tls has the server sign the handshake with the key of the
//     certificate it presented, whatever InsecureSkipVerify is. The pin
//     matched, so this is not ErrPinMismatch: it is ErrHandshakeRefused, as
//     is every handshake that whoever is on the path makes fail;
//   - such a transport sends no request to another host or another port than
//     the pinned ones: that is ErrPinMismatch too, with the request's body
//     closed and nothing dialed, a redirect's target included;
//   - it takes no proxy, the environment's included;
//   - a Pin given with Roots, with a Proxy or with Cleartext panics when the
//     transport is made: a pinned transport consults no roots, takes no
//     proxy, and has nothing to verify a cleartext connection with;
//   - the zero Pin is none, and changes nothing.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forkcloser/go-xhttp"
)

// device makes the certificate of a server no authority vouches for and no
// client would otherwise trust: signed by its own key, or by parent's when
// there is one, with no name a client could match and dates that are past.
// It returns the certificate with its key, and its SHA-256 in hexadecimal.
func device(t *testing.T, parent *tls.Certificate) (tls.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "a device"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
	}

	issuer, signer := template, any(key)
	if parent != nil {
		issuer, signer = parent.Leaf, parent.PrivateKey
	}

	encoded, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}

	made := tls.Certificate{Certificate: [][]byte{encoded}, PrivateKey: key, Leaf: leaf}
	if parent != nil {
		made.Certificate = append(made.Certificate, parent.Certificate...)
	}

	sum := sha256.Sum256(encoded)

	return made, hex.EncodeToString(sum[:])
}

// presenting starts a TLS server that presents certificate, over HTTP/2 when
// major is 2, and returns its host and port.
func presenting(t *testing.T, certificate tls.Certificate, major int, handler http.HandlerFunc) string {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.EnableHTTP2 = major == 2
	server.StartTLS()
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "https://")
}

// pinned is NewPin for arguments the test knows to be good.
func pinned(t *testing.T, server, fingerprint string) xhttp.Pin {
	t.Helper()

	pin, err := xhttp.NewPin(server, fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	return pin
}

// through asks a client that has pin for address.
func through(t *testing.T, pin xhttp.Pin, address string) (int, error) {
	t.Helper()

	return get(t.Context(), t, xhttp.NewClient(xhttp.Config{Pin: pin}), address)
}

// notTrusted reports whether err is of a certificate crypto/tls could not
// verify, which is what a server is to a transport that has no pin of it.
func notTrusted(err error) bool {
	_, is := errors.AsType[*tls.CertificateVerificationError](err)

	return is
}

// asOpenSSLPrints is a fingerprint in capitals, a colon between two bytes.
func asOpenSSLPrints(fingerprint string) string {
	var pairs []string

	for at := 0; at < len(fingerprint); at += 2 {
		pairs = append(pairs, strings.ToUpper(fingerprint[at:at+2]))
	}

	return strings.Join(pairs, ":")
}

// TestNewPin: a host and a SHA-256 in either of its two written forms make a
// pin, the same pin; anything else is ErrPin.
func TestNewPin(t *testing.T) {
	t.Parallel()

	const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	const shown = "device.test:443 pinned to " + fingerprint

	for name, written := range map[string]string{
		"64 digits":              fingerprint,
		"64 digits in capitals":  strings.ToUpper(fingerprint),
		"32 pairs and colons":    asOpenSSLPrints(fingerprint),
		"pairs in small letters": strings.ToLower(asOpenSSLPrints(fingerprint)),
	} {
		pin, err := xhttp.NewPin("device.test", written)
		if err != nil || pin.String() != shown {
			t.Errorf("%s: %v, %v; want %s", name, pin, err, shown)
		}
	}

	if pin := pinned(t, "[::1]:8443", fingerprint); pin.String() != "[::1]:8443 pinned to "+fingerprint {
		t.Errorf("a pin of an address and a port is %v", pin)
	}

	if none := (xhttp.Pin{}).String(); none != "no pin" {
		t.Errorf("the zero Pin is %q", none)
	}

	for name, given := range map[string][2]string{
		"no host":                         {"", fingerprint},
		"a URL for a host":                {"https://device.test", fingerprint},
		"a host and a path":               {"device.test/admin", fingerprint},
		"a host outside ASCII":            {"σ.test", fingerprint},
		"a port that is no number":        {"device.test:https", fingerprint},
		"an IPv6 address with no bracket": {"::1", fingerprint},
		"no fingerprint":                  {"device.test", ""},
		"62 digits":                       {"device.test", fingerprint[2:]},
		"63 digits":                       {"device.test", fingerprint[1:]},
		"65 digits":                       {"device.test", fingerprint + "0"},
		"66 digits":                       {"device.test", fingerprint + "00"},
		"128 digits":                      {"device.test", fingerprint + fingerprint},
		"a digit that is none":            {"device.test", "g" + fingerprint[1:]},
		"a space before":                  {"device.test", " " + fingerprint},
		"a line after":                    {"device.test", fingerprint + "\n"},
		"the name of the hash before":     {"device.test", "sha256:" + fingerprint},
		"a SHA-1, in pairs":               {"device.test", asOpenSSLPrints(fingerprint[:40])},
		"pairs with a hyphen between":     {"device.test", strings.ReplaceAll(asOpenSSLPrints(fingerprint), ":", "-")},
		"pairs with one colon missing":    {"device.test", strings.Replace(asOpenSSLPrints(fingerprint), ":", "", 1) + "0"},
		"95 digits":                       {"device.test", strings.Repeat("0", 95)},
		"pairs and a colon at the end":    {"device.test", asOpenSSLPrints(fingerprint[:62]) + ":0:"},
		"colons where digits go":          {"device.test", strings.Repeat(":", 64)},
		"a base64 of the same hash":       {"device.test", "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="},
	} {
		pin, err := xhttp.NewPin(given[0], given[1])
		if !errors.Is(err, xhttp.ErrPin) || pin.String() != "no pin" {
			t.Errorf("%s: %v, %v; want no pin and ErrPin", name, pin, err)
		}
	}
}

// TestAPinnedServerIsTrustedByItsCertificateAlone: a certificate that is
// signed by itself, bears no name and is out of date is no server's to any
// other transport, and is the pinned server's to one that has its pin, over
// both protocols, whichever way the fingerprint is written, and whether the
// server is pinned by its address or under a name.
func TestAPinnedServerIsTrustedByItsCertificateAlone(t *testing.T) {
	t.Parallel()

	certificate, fingerprint := device(t, nil)

	for _, major := range []int{1, 2} {
		server := presenting(t, certificate, major, func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != major {
				t.Errorf("a request came over HTTP/%d, want HTTP/%d", r.ProtoMajor, major)
			}

			_, _ = w.Write([]byte("content"))
		})

		if _, err := get(t.Context(), t, xhttp.NewClient(xhttp.Config{}), "https://"+server); !notTrusted(err) {
			t.Fatalf("HTTP/%d, with no pin: %v, want a certificate that is not trusted", major, err)
		}

		_, port, _ := strings.Cut(server, ":")

		named := "localhost:" + port

		for _, reached := range []struct {
			by, address string
			pin         xhttp.Pin
		}{
			{"its address, in 64 digits", server, pinned(t, server, fingerprint)},
			{"its address, in pairs", server, pinned(t, server, asOpenSSLPrints(fingerprint))},
			{"a name", named, pinned(t, named, fingerprint)},
			{"a name in other letters", named, pinned(t, "LocalHost:"+port, strings.ToUpper(fingerprint))},
		} {
			status, err := through(t, reached.pin, "https://"+reached.address)
			if err != nil || status != http.StatusOK {
				t.Errorf("HTTP/%d, pinned by %s: %d, %v; want 200", major, reached.by, status, err)
			}
		}
	}
}

// TestAnotherCertificateIsNotThePinnedServer: a server that presents another
// certificate than the pinned one is ErrPinMismatch, with the fingerprint it
// presented, and hears nothing of the request. The certificate that signed
// the server's is another certificate: the pin is of the first one.
func TestAnotherCertificateIsNotThePinnedServer(t *testing.T) {
	t.Parallel()

	authority, ofTheAuthority := device(t, nil)
	signed, ofTheSigned := device(t, &authority)
	_, ofAnother := device(t, nil)

	for _, major := range []int{1, 2} {
		var heard atomic.Int32

		server := presenting(t, signed, major, func(http.ResponseWriter, *http.Request) { heard.Add(1) })

		for name, fingerprint := range map[string]string{
			"a certificate the server does not have":   ofAnother,
			"the certificate that signed the server's": ofTheAuthority,
		} {
			_, err := through(t, pinned(t, server, fingerprint), "https://"+server)

			switch {
			case !errors.Is(err, xhttp.ErrPinMismatch):
				t.Errorf("HTTP/%d, pinned to %s: %v, want ErrPinMismatch", major, name, err)
			case errors.Is(err, xhttp.ErrHandshakeRefused), notTrusted(err):
				t.Errorf(
					"HTTP/%d, pinned to %s: %v is a refused handshake, or a certificate not trusted",
					major,
					name,
					err,
				)
			case !strings.Contains(err.Error(), ofTheSigned) || !strings.Contains(err.Error(), fingerprint):
				t.Errorf("HTTP/%d, pinned to %s: %v holds no fingerprint pinned, or none presented", major, name, err)
			}
		}

		if heard.Load() != 0 {
			t.Errorf("HTTP/%d: a server that is not the pinned one heard %d requests", major, heard.Load())
		}

		status, err := through(t, pinned(t, server, ofTheSigned), "https://"+server)
		if err != nil || status != http.StatusOK || heard.Load() != 1 {
			t.Errorf("HTTP/%d, pinned to the server's own certificate, its chain behind it: %d, %v, heard %d times",
				major, status, err, heard.Load())
		}
	}
}

// TestThePinnedCertificateWithoutItsKeyCompletesNoHandshake: the certificate
// is public, and a server that presents it with a key of its own is what
// stands between a client and the pinned server. Where the server that
// holds the key is reached, in TLS 1.3 at every level and in TLS 1.2 at
// Legacy, the one that does not fails the handshake and hears nothing of the
// request; the error is the handshake's, not the pin's.
func TestThePinnedCertificateWithoutItsKeyCompletesNoHandshake(t *testing.T) {
	t.Parallel()

	certificate, fingerprint := device(t, nil)
	another, _ := device(t, nil)

	// The pinned certificate, and the key of another.
	keyless := tls.Certificate{
		Certificate: certificate.Certificate, Leaf: certificate.Leaf, PrivateKey: another.PrivateKey,
	}

	// serving starts a server of one TLS version that presents presented,
	// and returns its address and the count of the requests it hears.
	serving := func(presented tls.Certificate, version uint16) (string, *atomic.Int32) {
		var heard atomic.Int32

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			heard.Add(1)
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{presented}, MinVersion: version, MaxVersion: version}
		server.StartTLS()
		t.Cleanup(server.Close)

		return strings.TrimPrefix(server.URL, "https://"), &heard
	}

	for name, reached := range map[string]struct {
		version uint16
		levels  []xhttp.TLSLevel
	}{
		"TLS 1.3": {tls.VersionTLS13, []xhttp.TLSLevel{xhttp.HybridOnly, xhttp.Classical, xhttp.Legacy}},
		"TLS 1.2": {tls.VersionTLS12, []xhttp.TLSLevel{xhttp.Legacy}},
	} {
		holder, _ := serving(certificate, reached.version)
		impostor, heard := serving(keyless, reached.version)

		for _, level := range reached.levels {
			to := func(server string) (int, error) {
				client := xhttp.NewClient(xhttp.Config{Pin: pinned(t, server, fingerprint), TLS: level})

				return get(t.Context(), t, client, "https://"+server)
			}

			if status, err := to(holder); err != nil || status != http.StatusOK {
				t.Errorf("%s, level %d, the server that holds the key: %d, %v; want 200", name, level, status, err)
			}

			_, err := to(impostor)
			if !errors.Is(err, xhttp.ErrHandshakeRefused) || errors.Is(err, xhttp.ErrPinMismatch) || notTrusted(err) {
				t.Errorf("%s, level %d, a server without the key: %v, want ErrHandshakeRefused alone", name, level, err)
			}
		}

		if heard.Load() != 0 {
			t.Errorf("%s: a server without the pinned key heard %d requests", name, heard.Load())
		}
	}
}

// TestAPinnedTransportReachesNoOtherHost: a request for another host, or for
// the pinned host on another port, is ErrPinMismatch: its body is closed
// and nothing is dialed, the target of a redirect included, even a server
// that presents the pinned certificate.
func TestAPinnedTransportReachesNoOtherHost(t *testing.T) {
	t.Parallel()

	certificate, fingerprint := device(t, nil)

	var elsewhere atomic.Int32

	// The same certificate at another port: the pin is of a host, too.
	other := presenting(t, certificate, 1, func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) })

	server := presenting(t, certificate, 1, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			http.Redirect(w, r, "https://"+other+"/", http.StatusTemporaryRedirect)
		}
	})

	_, port, _ := strings.Cut(server, ":")

	transport := xhttp.NewTransport(xhttp.Config{Pin: pinned(t, server, fingerprint)})

	for name, address := range map[string]string{
		"the same certificate at another port": "https://" + other + "/",
		"the pinned port under another name":   "https://localhost:" + port + "/",
		"the pinned host and no port":          "https://127.0.0.1/",
		"another host":                         "https://server.test/",
	} {
		body := &closing{Reader: strings.NewReader("content")}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, address, body)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := transport.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}

		if !errors.Is(err, xhttp.ErrPinMismatch) || !body.closed.Load() {
			t.Errorf("%s: %v, the body closed: %t; want ErrPinMismatch and closed", name, err, body.closed.Load())
		}
	}

	client := &http.Client{Transport: transport}

	if status, err := get(t.Context(), t, client, "https://"+server+"/"); err != nil || status != http.StatusOK {
		t.Errorf("the pinned host: %d, %v; want 200", status, err)
	}

	if _, err := get(t.Context(), t, client, "https://"+server+"/away"); !errors.Is(err, xhttp.ErrPinMismatch) {
		t.Errorf("a redirect from the pinned host to another: %v, want ErrPinMismatch", err)
	}

	if elsewhere.Load() != 0 {
		t.Errorf("a server that is not the pinned host heard %d requests", elsewhere.Load())
	}
}

// TestAPinExcludesWhatItReplaces: with a Pin, Roots, a Proxy and Cleartext
// each panic when the transport is made; the zero Pin excludes nothing.
func TestAPinExcludesWhatItReplaces(t *testing.T) {
	t.Parallel()

	panics := func(config xhttp.Config) (panicked bool) {
		defer func() { panicked = recover() != nil }()

		xhttp.NewTransport(config)

		return false
	}

	pin := pinned(t, "device.test", strings.Repeat("ab", sha256.Size))

	for name, with := range map[string]func(*xhttp.Config){
		"Roots":     func(config *xhttp.Config) { config.Roots = x509.NewCertPool() },
		"a Proxy":   func(config *xhttp.Config) { config.Proxy = http.ProxyFromEnvironment },
		"Cleartext": func(config *xhttp.Config) { config.Cleartext = true },
	} {
		excluded := xhttp.Config{Pin: pin}
		with(&excluded)

		if !panics(excluded) {
			t.Errorf("a Pin with %s: NewTransport did not panic", name)
		}

		alone := xhttp.Config{}
		with(&alone)

		if panics(alone) {
			t.Errorf("%s with no Pin: NewTransport panicked", name)
		}
	}

	if panics(xhttp.Config{Pin: pin, TLS: xhttp.Legacy, UserAgent: "contract/1", StallTimeout: -1, Offline: true}) {
		t.Error("a Pin with a level, a User-Agent, a stall timeout and Offline: NewTransport panicked")
	}
}

// TestAPinnedTransportTakesNoProxy: the environment's proxy is not asked for
// the pinned host. net/http reads the environment once for a process, so the
// request is made by this test binary run again, with an environment of its
// own. The pinned host is an address of the range kept for documentation
// (RFC 5737), where nothing answers: not this machine, for which net/http
// asks no proxy whatever the environment says, and not a name, which a
// network that answers every name would give a server to.
func TestAPinnedTransportTakesNoProxy(t *testing.T) {
	t.Parallel()

	const target = "XHTTP_TEST_PINNED"

	if server := os.Getenv(target); server != "" {
		// The second run. The request is the pinned host's, so it is not
		// refused, and ends in the dialing: at once where no route leads
		// there, after these five seconds where nothing answers.
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		client := xhttp.NewClient(xhttp.Config{Pin: pinned(t, server, strings.Repeat("ab", sha256.Size))})

		_, err := get(ctx, t, client, (&url.URL{Scheme: "https", Host: server}).String())
		if err == nil || errors.Is(err, xhttp.ErrPinMismatch) {
			t.Errorf("a request for the pinned host, where nothing answers: %v, want an error of the dialing", err)
		}

		return
	}

	proxy := proxying(t, false)

	again := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAPinnedTransportTakesNoProxy$")

	again.Env = append(os.Environ(),
		"HTTPS_PROXY="+proxy.server.URL, "https_proxy="+proxy.server.URL,
		"NO_PROXY=", "no_proxy=",
		target+"=192.0.2.1",
	)

	if output, err := again.CombinedOutput(); err != nil {
		t.Fatalf("the second run: %v\n%s", err, output)
	}

	if seen := proxy.took(); len(seen) != 0 {
		t.Errorf("the proxy the environment names was asked %+v by a pinned transport", seen)
	}
}

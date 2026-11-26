package xhttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Config is what varies between transports. The zero value is the baseline:
// https only, HybridOnly, the system's roots, the environment's proxy.
type Config struct {
	// KeyExchange is the level of every connection the transport makes.
	KeyExchange KeyExchange
	// Roots is the certificate authorities trusted; the system's when nil.
	Roots *x509.CertPool
	// Certificates is what the client presents to a server that asks.
	Certificates []tls.Certificate
	// Proxy picks a request's proxy; http.ProxyFromEnvironment when nil.
	Proxy func(*http.Request) (*url.URL, error)
	// StallTimeout is how long a read of a response body may wait for a
	// byte before it fails with [ErrStalled]. Zero is one minute; a
	// negative value waits for ever.
	StallTimeout time.Duration
	// UserAgent is the User-Agent of a request that has no such header;
	// Go's own when empty.
	UserAgent string
	// Cleartext sends a request that is not https. Without it, such a
	// request fails with [ErrCleartext].
	Cleartext bool
	// Offline fails every request with [ErrOffline], before anything is
	// dialed.
	Offline bool
}

// NewClient returns a client on a transport under config, which follows
// redirects as [Redirects] does, ten of them. It panics as [NewTransport]
// does.
func NewClient(config Config) *http.Client {
	const redirects = 10

	return &http.Client{
		Transport:     NewTransport(config),
		CheckRedirect: Redirects(redirects),
	}
}

// Redirects is an http.Client.CheckRedirect that follows at most limit
// redirects, and none from https to anything else: either is [ErrRedirect].
// A redirect it lets through is still the transport's to carry.
func Redirects(limit int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > limit {
			return fmt.Errorf("%w: more than %d", ErrRedirect, limit)
		}

		if req.URL.Scheme != https && via[len(via)-1].URL.Scheme == https {
			return fmt.Errorf("%w: from https to %s://%s", ErrRedirect, req.URL.Scheme, req.URL.Host)
		}

		return nil
	}
}

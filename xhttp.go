package xhttp

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Config is what varies between transports. The zero value is the baseline:
// https only, HybridOnly, the system's roots, the environment's proxy.
type Config struct {
	// TLS is the level of every connection the transport makes.
	TLS TLSLevel
	// Roots is the certificate authorities trusted; the system's when nil.
	Roots *x509.CertPool
	// Proxy picks a request's proxy; http.ProxyFromEnvironment when nil.
	Proxy func(*http.Request) (*url.URL, error)
	// StallTimeout is how long the server may stay silent: before it takes
	// more of the request's body, before its response begins once the
	// request is sent, and then while a read of the response's body waits
	// for a byte. Past it the request, or the read,
	// fails with [ErrStalled]. The caller's own time is not counted: what
	// its request body takes to give its content, and what it takes between
	// two reads of the response. Zero is one minute; a negative value waits
	// for ever, with the request's context as the one limit.
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

// NewClient returns a client on a transport under config, which follows at
// most ten redirects: one more is [ErrRedirect]. It panics as [NewTransport]
// does.
func NewClient(config Config) *http.Client {
	const most = 10

	return &http.Client{
		Transport: NewTransport(config),
		// via is the requests made so far: the first, and one for each
		// redirect followed.
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > most {
				return fmt.Errorf("%w: more than %d", ErrRedirect, most)
			}

			return nil
		},
	}
}

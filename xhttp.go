// Copyright Mycophonic.
// Copyright Forkcloser.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package xhttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var (
	// ErrOffline is the error of every request through an offline transport.
	ErrOffline = errors.New("offline")
	// ErrCleartext is the error of a request that is not https, through a
	// transport that was not told to send one.
	ErrCleartext = errors.New("not https")
	// ErrHandshakeRefused is the error of a TLS alert from the server: most
	// often a server that offers no key exchange, or no TLS version, the
	// transport's level accepts. A server that turns down the client's
	// certificate says so with an alert too, and with TLS 1.3 after the
	// client's side of the handshake is done.
	ErrHandshakeRefused = errors.New("the server refused the TLS handshake")
	// ErrStalled is the error of a response body that stopped arriving.
	ErrStalled = errors.New("the response body stopped arriving")
	// ErrRedirect is the error of a redirect the client does not follow.
	ErrRedirect = errors.New("redirect refused")
)

const (
	// DefaultStallTimeout is how long a read of a response body waits for a
	// byte under a Config that names no StallTimeout.
	DefaultStallTimeout = time.Minute
	// DefaultRedirects is how many redirects a client from NewClient follows.
	DefaultRedirects = 10
)

// KeyExchange is what a transport's connections may agree their keys with,
// and under which TLS versions. The zero value is the strictest, and each one
// after it gives something up.
type KeyExchange int

const (
	// HybridOnly is TLS 1.3 with a post-quantum hybrid key exchange, and
	// nothing else.
	HybridOnly KeyExchange = iota
	// Classical is TLS 1.3 with any key exchange Go offers, the classical
	// ones included, for a server that has no hybrid.
	Classical
	// Legacy is TLS as Go defaults it, 1.2 included, for a server that has
	// no TLS 1.3.
	Legacy
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
	// byte before it fails with [ErrStalled]. Zero is DefaultStallTimeout;
	// a negative value waits for ever.
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
// redirects as [Redirects] does, DefaultRedirects of them. It panics as
// [NewTransport] does.
func NewClient(config Config) *http.Client {
	return &http.Client{
		Transport:     NewTransport(config),
		CheckRedirect: Redirects(DefaultRedirects),
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

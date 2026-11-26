// Copyright Mycophonic.
// Copyright Forkcloser.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package xhttp

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Credential is a token and the hosts it is for. It is sent to those hosts,
// over https, and to no other: not to a host a redirect leads to, and not in
// cleartext.
type Credential struct {
	// Scheme is the Authorization scheme, "Bearer" when empty.
	Scheme string
	// Token is the credential itself. A credential with no token is never
	// sent.
	Token string
	// Hosts is who the token is for: a host name, which stands for its
	// https port, or host:port, an IPv6 address in brackets. The name is
	// the whole name: a credential for example.com is not for
	// www.example.com.
	Hosts []string
}

// Authorize returns a transport that carries each request through base, with
// the first of credentials that is for its host. A request that already has
// an Authorization header keeps it. It panics on a nil base.
func Authorize(base http.RoundTripper, credentials ...Credential) http.RoundTripper {
	if base == nil {
		panic("xhttp: Authorize needs a transport to carry the requests")
	}

	return &authorizer{base: base, credentials: credentials}
}

type authorizer struct {
	base        http.RoundTripper
	credentials []Credential
}

func (a *authorizer) RoundTrip(req *http.Request) (*http.Response, error) {
	credential, found := a.pick(req)
	if !found {
		return a.base.RoundTrip(req) //nolint:wrapcheck // the base's own error, unchanged
	}

	scheme := credential.Scheme
	if scheme == "" {
		scheme = "Bearer"
	}

	// A RoundTripper leaves the caller's request as it is. Not Request.Clone:
	// it copies Trailer, which a caller fills while the body is read.
	sent := req.WithContext(req.Context())
	sent.Header = req.Header.Clone()
	sent.Header.Set("Authorization", scheme+" "+credential.Token)

	resp, err := a.base.RoundTrip(sent)
	if err != nil || resp == nil {
		return resp, err //nolint:wrapcheck // the base's own error, unchanged
	}

	// The caller gets its own request back, not the copy that has the token.
	resp.Request = req

	return resp, nil
}

// CloseIdleConnections forwards to base.
func (a *authorizer) CloseIdleConnections() {
	if closer, ok := a.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// pick is the credential a request gets, if any.
func (a *authorizer) pick(req *http.Request) (Credential, bool) {
	// A request with no URL or no header map is the base's to refuse.
	if req.URL == nil || req.Header == nil || req.URL.Scheme != https {
		return Credential{}, false
	}

	if _, named := req.Header["Authorization"]; named {
		return Credential{}, false
	}

	for _, credential := range a.credentials {
		if credential.Token != "" && credential.covers(req.URL) {
			return credential, true
		}
	}

	return Credential{}, false
}

const httpsPort = "443"

func (c Credential) covers(target *url.URL) bool {
	port := target.Port()
	if port == "" {
		port = httpsPort
	}

	for _, host := range c.Hosts {
		name, named, err := net.SplitHostPort(host)
		if err != nil {
			// No port: the host alone, which a URL writes in brackets when
			// it is an IPv6 address and Hostname gives without them. The
			// pair of them only: a stray bracket is part of a name that
			// matches no host.
			name, named = host, httpsPort
			if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
				name = host[1 : len(host)-1]
			}
		}

		if named == port && strings.EqualFold(name, target.Hostname()) {
			return true
		}
	}

	return false
}

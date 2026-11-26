package xhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Credential is a token and the hosts it is for, made by [NewCredential]. It
// is sent to those hosts, over https, and to no other: not to a host a
// redirect leads to, and not in cleartext. Nor is it sent with a request a
// client makes on a redirect, unless every request that led there was https
// and for a host it names: another host would be choosing what the token is
// presented for. The zero Credential names no host and is never sent.
type Credential struct {
	// header is the Authorization field's value, scheme and token.
	header string
	hosts  []host
}

// host is one host a credential is for: a name or an address, and a port.
type host struct {
	// name is in lower case, and empty when the host is an address.
	name string
	addr netip.Addr
	port uint16
}

var (
	errNotAHost = errors.New("neither a name, nor an IPv4 address, nor an IPv6 address in brackets with no zone")
	errNoPort   = errors.New("the port is not a number from 1 to 65535")
)

const (
	// del is the one control character past the space.
	del              = 0x7f
	httpsPort uint16 = 443
	// The longest name the DNS carries, and the longest of its labels.
	longestName, longestLabel = 253, 63
)

// NewCredential returns the credential that sends "scheme token" as the
// Authorization of a request for one of hosts.
//
// A host is written in ASCII, as a URL writes it: a name or an IPv4 address,
// or an IPv6 address in brackets and with no zone, alone for the https port
// or followed by a colon and a port. The name is the whole name: a credential
// for example.com is not for www.example.com. An international name is given
// in its "xn--" form, and a request whose URL writes its host outside ASCII
// gets no credential.
//
// What would not arrive as it is, or could never match, is [ErrCredential]:
// a scheme that is not an HTTP token; a token that is empty, holds a control
// character other than a tab, or has a space or a tab at one end, which is
// read as the separator after the scheme at its start, and dropped with the
// end of the header field at its end; no host at all; a host in another
// form. The error names the argument and never holds the token.
func NewCredential(scheme, token string, hosts ...string) (Credential, error) {
	if scheme == "" || strings.ContainsFunc(scheme, func(char rune) bool { return !tokenChar(char) }) {
		return Credential{}, fmt.Errorf("%w: scheme %q is not an HTTP token", ErrCredential, scheme)
	}

	if !fieldValue(token) {
		return Credential{}, fmt.Errorf(
			"%w: the token is empty, holds a control character, or has a space or a tab at one end",
			ErrCredential,
		)
	}

	if len(hosts) == 0 {
		return Credential{}, fmt.Errorf("%w: no host is named", ErrCredential)
	}

	made := Credential{header: scheme + " " + token, hosts: make([]host, 0, len(hosts))}

	for _, written := range hosts {
		parsed, err := parseHost(written)
		if err != nil {
			return Credential{}, fmt.Errorf("%w: host %q: %w", ErrCredential, written, err)
		}

		made.hosts = append(made.hosts, parsed)
	}

	return made, nil
}

// fieldValue reports whether text, after a scheme and a space, is sent in a
// header field and read back as it is (RFC 9110, sections 5.5 and 11.4): not
// empty, no control character but a tab, and neither a space nor a tab at an
// end. One at the start is carried, and read as more of the separator.
func fieldValue(text string) bool {
	blank := func(octet byte) bool { return octet == ' ' || octet == '\t' }

	if text == "" || blank(text[0]) || blank(text[len(text)-1]) {
		return false
	}

	// Octets, not runes: a field carries those past ASCII as they are.
	for at := range len(text) {
		if octet := text[at]; octet < ' ' && octet != '\t' || octet == del {
			return false
		}
	}

	return true
}

// tokenChar reports whether char is one an HTTP token is made of.
func tokenChar(char rune) bool {
	switch {
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		return true
	default:
		return strings.ContainsRune("!#$%&'*+-.^_`|~", char)
	}
}

// Authorize returns a transport that carries each request through base, with
// the first of credentials that is for its host. A request that already has
// an Authorization header keeps it. It panics on a nil base.
func Authorize(base http.RoundTripper, credentials ...Credential) http.RoundTripper {
	if base == nil {
		panic("xhttp: Authorize needs a transport to carry the requests")
	}

	return &authorizer{base: base, credentials: slices.Clone(credentials)}
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

	// A RoundTripper leaves the caller's request as it is. Not Request.Clone:
	// it copies Trailer, which a caller fills while the body is read.
	sent := req.WithContext(req.Context())
	sent.Header = req.Header.Clone()
	sent.Header.Set("Authorization", credential.header)

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
		// The first that names the host decides: when a redirect withholds
		// it, no other is sent in its place.
		if credential.covers(req.URL) {
			return credential, credential.led(req)
		}
	}

	return Credential{}, false
}

// led reports whether every request that led to req, which a client makes
// by following redirects, was https and for a host the credential names.
func (c Credential) led(req *http.Request) bool {
	for via := req.Response; via != nil; via = via.Request.Response {
		// A response that names no request tells nothing of where it
		// came from.
		if via.Request == nil || via.Request.URL == nil ||
			via.Request.URL.Scheme != https || !c.covers(via.Request.URL) {
			return false
		}
	}

	return true
}

// covers reports whether target's host is one the credential is for. The
// standard library dials a name that is ASCII as the URL writes it, and
// another by a conversion this package does not have: only ASCII matches.
func (c Credential) covers(target *url.URL) bool {
	port := httpsPort

	if written := target.Port(); written != "" {
		number, err := strconv.ParseUint(written, 10, 16)
		if err != nil {
			return false
		}

		port = uint16(number)
	}

	name := target.Hostname()
	addr, err := netip.ParseAddr(name)
	isAddr := err == nil

	return slices.ContainsFunc(c.hosts, func(named host) bool {
		switch {
		case named.port != port:
			return false
		case named.addr.IsValid():
			return isAddr && named.addr == addr
		default:
			return !isAddr && named.name == lowerASCII(name)
		}
	})
}

// parseHost reads one host of a credential.
func parseHost(written string) (host, error) {
	name, port, err := splitHost(written)
	if err != nil {
		return host{}, err
	}

	parsed := host{port: httpsPort}

	if port != "" {
		number, notANumber := strconv.ParseUint(port, 10, 16)
		if notANumber != nil || number == 0 {
			return host{}, errNoPort
		}

		parsed.port = uint16(number)
	}

	bracketed := strings.HasPrefix(written, "[")
	addr, err := netip.ParseAddr(name)

	switch {
	case err == nil && addr.Is6() != bracketed:
		// An IPv6 address is in brackets, and nothing else is.
		return host{}, errNotAHost
	case err == nil && addr.Zone() != "":
		// A URL writes a zone's percent sign as %25 and gives it back as %,
		// and netip takes any text for a zone, a bracket included.
		return host{}, errNotAHost
	case err == nil:
		parsed.addr = addr
	case bracketed || !dnsName(name):
		return host{}, errNotAHost
	default:
		parsed.name = lowerASCII(name)
	}

	return parsed, nil
}

// splitHost cuts a host into its name, without the brackets it may be in,
// and the port written after it, which is empty when none is.
func splitHost(written string) (name, port string, err error) {
	if !strings.HasPrefix(written, "[") {
		var ported bool

		name, port, ported = strings.Cut(written, ":")
		if ported && port == "" {
			return "", "", errNoPort
		}

		return name, port, nil
	}

	name, rest, closed := strings.Cut(written[1:], "]")

	switch {
	case !closed:
		return "", "", errNotAHost
	case rest == "":
		return name, "", nil
	}

	port, ported := strings.CutPrefix(rest, ":")

	switch {
	case !ported:
		return "", "", errNotAHost
	case port == "":
		return "", "", errNoPort
	default:
		return name, port, nil
	}
}

// dnsName reports whether name is made as a host name is: labels of ASCII
// letters, digits, hyphens and underscores, with a dot between two.
func dnsName(name string) bool {
	if len(name) > longestName {
		return false
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > longestLabel {
			return false
		}

		for _, char := range label {
			switch {
			case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			case char == '-', char == '_':
			default:
				return false
			}
		}
	}

	return true
}

// lowerASCII is name with its ASCII capitals in lower case, and nothing else
// changed: strings.ToLower also maps letters outside ASCII onto ASCII ones.
func lowerASCII(name string) string {
	return strings.Map(func(char rune) rune {
		if char >= 'A' && char <= 'Z' {
			return char + ('a' - 'A')
		}

		return char
	}, name)
}

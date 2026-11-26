package xhttp

import "errors"

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
	// ErrStalled is the error of a server that stayed silent for longer than
	// [Config.StallTimeout]: its response did not begin once the request was
	// sent, or the response's body stopped arriving.
	ErrStalled = errors.New("the server went silent")
	// ErrRedirect is the error of a redirect the client does not follow.
	ErrRedirect = errors.New("redirect refused")
	// ErrCredential is the error of [NewCredential] for what would not
	// arrive as it is, or could never match a request.
	ErrCredential = errors.New("not a credential")
)

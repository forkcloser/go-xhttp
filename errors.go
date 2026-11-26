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
	// ErrStalled is the error of a response body that stopped arriving.
	ErrStalled = errors.New("the response body stopped arriving")
	// ErrRedirect is the error of a redirect the client does not follow.
	ErrRedirect = errors.New("redirect refused")
)

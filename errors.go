package xhttp

import "errors"

var (
	// ErrOffline is the error of every request through an offline transport.
	ErrOffline = errors.New("offline")
	// ErrCleartext is the error of a request that is not https, or whose
	// proxy is given credentials and is not reached over https, through a
	// transport that was not told to send cleartext.
	ErrCleartext = errors.New("not https")
	// ErrHandshakeRefused is the error of a TLS handshake that failed, when
	// neither the server's certificate nor the network is the cause: most
	// often a server that offers no key exchange, or no TLS version, the
	// transport's [TLSLevel] accepts, whichever side ends the handshake over
	// it.
	// A failure of the server's own in the middle of a handshake is in it
	// too, and may pass at another attempt: nothing tells the two apart.
	// Nor does it say whose doing it was: nothing that ends a handshake is
	// authenticated, and whoever is on the path can end one. Under a [Pin],
	// a server that presents the pinned certificate and cannot prove it
	// holds its key ends in it too, and not in [ErrPinMismatch].
	// What a server says once the handshake is done is not in it.
	ErrHandshakeRefused = errors.New("the TLS handshake failed")
	// ErrStalled is the error of a server that stayed silent for longer than
	// [Config.StallTimeout]: it stopped taking the request, its response did
	// not begin once the request was sent, or the response's body stopped
	// arriving.
	ErrStalled = errors.New("the server went silent")
	// ErrRedirect is the error of a redirect that is not followed: one that
	// leads from https to another scheme, which no transport carries, and
	// one past the ten a client from [NewClient] follows.
	ErrRedirect = errors.New("redirect refused")
	// ErrCredential is the error of [NewCredential] for what would not
	// arrive as it is, or could never match a request.
	ErrCredential = errors.New("not a credential")
	// ErrPin is the error of [NewPin] for what is no host, or no SHA-256
	// fingerprint.
	ErrPin = errors.New("not a pin")
	// ErrPinMismatch is the error of a transport that has a [Pin] when what
	// it meets is not the pinned server: a request for another host, which
	// is not sent, or a server that presents another certificate, with
	// which the TLS handshake is not completed. It is the pin's own refusal
	// and no more: the pinned certificate in the hands of a server that
	// does not hold its key matches the pin, and fails the handshake as
	// [ErrHandshakeRefused].
	ErrPinMismatch = errors.New("not the pinned server")
)

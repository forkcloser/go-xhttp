// Package xhttp is the client side of net/http under a posture. [NewTransport]
// and [NewClient] return the standard library's own types, built from a
// [Config] whose zero value is the strictest setting: whatever is weaker is
// asked for by name. The package keeps no state of its own, so a library
// uses it as a program does: two transports share nothing but what the
// standard library shares, the system's roots and the proxy the environment
// names, which net/http reads once for the process. A transport, and a
// client on one, are safe for concurrent use, as the standard library's are.
//
// # The baseline
//
// A transport made from the zero Config:
//
//   - sends https only. A request with another scheme fails with
//     [ErrCleartext], unless [Config.Cleartext];
//   - speaks TLS 1.3 and agrees its keys with a post-quantum hybrid exchange,
//     or not at all ([HybridOnly]). [Classical] and [Legacy] give that up for
//     every connection of the transport that names them, and for no other: a
//     program that needs two levels makes two transports;
//   - fails with [ErrStalled] an exchange the server leaves waiting for a
//     minute: a request it has stopped taking, one whose response has not
//     begun, and the read of a response body that gets no byte
//     ([Config.StallTimeout]);
//   - waits 30 seconds for a connection and 10 for the TLS handshake, and
//     closes an HTTP/2 connection that answers no ping. The exchange as a
//     whole has no limit but the request's context;
//   - trusts the system's roots and takes its proxy from the environment,
//     unless [Config.Roots] or [Config.Proxy] say otherwise. A proxy that is
//     given credentials is reached over https, or the request fails with
//     [ErrCleartext]; one that is given none may be reached in cleartext,
//     and sees the host and port it is asked to connect to and no more of
//     an https request.
//
// A transport given a [Pin] is one server's instead: it trusts that server by
// the fingerprint of its certificate, whoever signed it, consults no root,
// takes no proxy, and sends no request to another host. That is for a server
// no authority vouches for, a device with a certificate of its own making.
//
// A transport carries no request that a redirect leads to from https to
// anything else, whatever client follows the redirect, and a client from
// [NewClient] follows at most ten: both are [ErrRedirect]. [Authorize] adds a
// token to the requests for the hosts its [Credential] names, over https, and
// to no other request, nor to one a redirect from another host led to.
//
// # Errors
//
// A fault the package itself raises wraps one of eight sentinels, each named
// for what a caller does on it:
//
//   - [ErrOffline]: the transport was told to be offline. Nothing was dialed.
//   - [ErrCleartext]: the request is not https, or its proxy's credentials
//     would travel in cleartext. Fix the URL, or make the transport with
//     Config.Cleartext.
//   - [ErrHandshakeRefused]: the TLS handshake failed, and neither the
//     server's certificate nor the network is the cause. Most often the
//     server has nothing the transport's level accepts, which no retry
//     changes and a weaker [TLSLevel] may. It is no word on who answered:
//     whoever is on the path can end a handshake, and under a [Pin] this is
//     also how a server ends that presents the pinned certificate and does
//     not hold its key.
//   - [ErrStalled]: the server went silent, in the middle of the request,
//     before its response, or in the middle of its body. What was read of a
//     body is the caller's, and so is asking for the rest.
//   - [ErrRedirect]: a redirect was not followed: it led from https to
//     another scheme, or it was one too many.
//   - [ErrCredential]: [NewCredential] was given what would not arrive as
//     it is, or could never match. Fix the argument the error names.
//   - [ErrPin]: [NewPin] was given what is no host, or no SHA-256
//     fingerprint. Fix the argument the error names.
//   - [ErrPinMismatch]: what a pinned transport met is not the pinned
//     server. Either the request is for another host, and was not sent, or
//     the server presents another certificate than the pinned one: it was
//     replaced, or something stands between. The error has the fingerprint
//     that was presented; nothing was sent over that connection. That
//     something stands between is not always this error: see
//     [ErrHandshakeRefused].
//
// Every other error is the standard library's and passes through unchanged.
//
// The retry subpackage wraps any transport with retries of what is safe to
// send again.
package xhttp

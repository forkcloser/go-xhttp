// Package xhttp is the client side of net/http under a posture. [NewTransport]
// and [NewClient] return the standard library's own types, built from a
// [Config] whose zero value is the strictest setting: whatever is weaker is
// asked for by name. Nothing in the package reads or writes a global, so a
// library uses it as a program does, and two transports share nothing.
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
//     unless [Config.Roots] or [Config.Proxy] say otherwise.
//
// A transport carries no request that a redirect leads to from https to
// anything else, whatever client follows the redirect, and a client from
// [NewClient] follows at most ten: both are [ErrRedirect]. [Authorize] adds a
// token to the requests for the hosts its [Credential] names, over https, and
// to no other request, nor to one a redirect from another host led to.
//
// # Errors
//
// A fault the package itself raises wraps one of six sentinels, each named
// for what a caller does on it:
//
//   - [ErrOffline]: the transport was told to be offline. Nothing was dialed.
//   - [ErrCleartext]: the request is not https. Fix the URL, or make the
//     transport with Config.Cleartext.
//   - [ErrHandshakeRefused]: the TLS handshake failed, and neither the
//     server's certificate nor the network is the cause. Most often the
//     server has nothing the transport's level accepts, which no retry
//     changes and a weaker [TLSLevel] may.
//   - [ErrStalled]: the server went silent, in the middle of the request,
//     before its response, or in the middle of its body. What was read of a
//     body is the caller's, and so is asking for the rest.
//   - [ErrRedirect]: a redirect was not followed: it led from https to
//     another scheme, or it was one too many.
//   - [ErrCredential]: [NewCredential] was given what would not arrive as
//     it is, or could never match. Fix the argument the error names.
//
// Every other error is the standard library's and passes through unchanged.
//
// The retry subpackage wraps any transport with retries of what is safe to
// send again.
package xhttp

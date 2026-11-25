// Copyright Mycophonic.
// Copyright Forkcloser.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

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
//   - fails the read of a response body that waits a minute for a byte, with
//     [ErrStalled] ([Config.StallTimeout]);
//   - waits 30 seconds for a connection, 10 for the TLS handshake and 30 for
//     the response's headers, and closes an HTTP/2 connection that answers no
//     ping. The exchange as a whole has no limit but the request's context;
//   - trusts the system's roots and takes its proxy from the environment,
//     unless [Config.Roots] or [Config.Proxy] say otherwise.
//
// A client from [NewClient] also follows at most [DefaultRedirects] redirects,
// and none from https to anything else ([Redirects]). [Authorize] adds a
// token to the requests for the hosts the token names, over https, and to no
// other request.
//
// # Errors
//
// A fault the posture itself raises wraps one of five sentinels, each named
// for what a caller does on it:
//
//   - [ErrOffline]: the transport was told to be offline. Nothing was dialed.
//   - [ErrCleartext]: the request is not https. Fix the URL, or make the
//     transport with Config.Cleartext.
//   - [ErrHandshakeRefused]: the server answered with a TLS alert. No retry
//     changes that; a weaker [KeyExchange] may, when the alert is for what
//     the transport offered and not for the client's certificate.
//   - [ErrStalled]: the body stopped arriving. What was read is the caller's,
//     and so is asking for the rest.
//   - [ErrRedirect]: a redirect was not followed.
//
// Every other error is the standard library's and passes through unchanged.
package xhttp

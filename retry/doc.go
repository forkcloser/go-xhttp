// Package retry sends a request again when that is safe and may help.
// [NewTransport] wraps any http.RoundTripper, one from xhttp or not:
//
//	client := xhttp.NewClient(xhttp.Config{})
//	client.Transport = retry.NewTransport(client.Transport, retry.Options{Retries: 3})
//
// # What is sent again
//
// A request whose attempt failed, or was answered 408, 429, 500, 502, 503 or
// 504, when sending it twice does what sending it once does: its method is
// GET, HEAD, OPTIONS, TRACE, PUT or DELETE, the idempotent methods of RFC 9110
// section 9.2.2, or it carries an Idempotency-Key or X-Idempotency-Key header,
// whatever its value, as net/http reads it. Any other request is sent again
// only when no connection could be made, since nothing was sent.
//
// A request with a body is sent again only if it has a GetBody, which
// http.NewRequest sets for a body in memory. One whose body is a stream is
// sent once.
//
// # What is not
//
// A failure no further attempt changes: the request's context is done; the
// certificate is not trusted; the host does not resolve; xhttp refused the
// request (xhttp.ErrOffline, xhttp.ErrCleartext) or the server refused the
// TLS handshake (xhttp.ErrHandshakeRefused); the request has no URL or no
// header map, which an http.RoundTripper is owed. Every other error is taken
// for one that may pass, one of the request's own making included: net/http
// gives those no type to tell them by.
//
// # What comes back
//
// The last attempt's answer, as its transport gave it: the response whatever
// its status, a 503 included, or the error, unchanged. The transport never
// makes an error of a response; the status is the caller's to read, as with
// any http.RoundTripper. That holds whenever a request is not sent again:
// no retry is left, the server asks for too long a wait, the context is done
// or its deadline falls before the wait would end, or the body cannot be
// read again after all.
//
// One case is an error of this package's making. A response that is to be
// retried is closed before the wait, and what the server had yet to send of
// it is not read; when the request's context is cancelled during that wait
// there is no answer left to give, and the error is the context's. It wraps
// the attempt's error when the attempt had failed, and names the status when
// it had been answered.
//
// # Waiting
//
// The wait before a retry starts at [Options.Backoff] and doubles, each wait
// a quarter longer or shorter at random, and is never longer than
// [Options.MaxBackoff]. A Retry-After header, in seconds or as a date, is
// obeyed when it asks for longer. A server that asks for more than MaxBackoff
// is not asked again, and its response comes back. A wait that would outlast
// the context's deadline is not begun.
//
// A retry is a log/slog record at the debug level, with the method, the host
// and the cause, and never the path or the query.
package retry

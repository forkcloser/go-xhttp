package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// https is the one scheme the baseline sends, and a credential travels.
const https = "https"

// The timeouts and the pool of every transport.
const (
	stallTimeout          = time.Minute // of a Config that names none
	dialTimeout           = 30 * time.Second
	dialKeepAlive         = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	idleConnTimeout       = 90 * time.Second
	expectContinueTimeout = time.Second
	// An HTTP/2 connection silent for pingAfter is pinged, and closed when
	// the ping gets no answer within pingTimeout: without it, a connection
	// the network dropped carries request after request to their timeouts.
	pingAfter           = 30 * time.Second
	pingTimeout         = 15 * time.Second
	maxIdleConns        = 100
	maxIdleConnsPerHost = 100
	maxConnsPerHost     = 100
)

type transport struct {
	base      *http.Transport
	stall     time.Duration // zero: the server's silence is never an error
	userAgent string
	cleartext bool
	offline   bool
}

// NewTransport returns a transport under config, with a connection pool of
// its own. Its CloseIdleConnections is the one http.Client calls. It panics
// on a KeyExchange there is none of.
func NewTransport(config Config) http.RoundTripper {
	proxy := config.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}

	stall := config.StallTimeout
	if stall == 0 {
		stall = stallTimeout
	}

	return &transport{
		base: &http.Transport{
			Proxy:                 proxy,
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig(config),
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			IdleConnTimeout:       idleConnTimeout,
			ExpectContinueTimeout: expectContinueTimeout,
			MaxIdleConns:          maxIdleConns,
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
			MaxConnsPerHost:       maxConnsPerHost,
			HTTP2:                 &http.HTTP2Config{SendPingTimeout: pingAfter, PingTimeout: pingTimeout},
		},
		stall:     max(stall, 0),
		userAgent: config.UserAgent,
		cleartext: config.Cleartext,
		offline:   config.Offline,
	}
}

func tlsConfig(config Config) *tls.Config {
	made := &tls.Config{ // #nosec G402 -- Legacy is Go's own floor, and a transport gets it only by name
		RootCAs:      config.Roots,
		Certificates: config.Certificates,
	}

	switch config.KeyExchange {
	case HybridOnly:
		made.MinVersion = tls.VersionTLS13
		made.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
	case Classical:
		made.MinVersion = tls.VersionTLS13
	case Legacy:
	default:
		panic(fmt.Sprintf("xhttp: there is no key exchange level %d", config.KeyExchange))
	}

	return made
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The standard transport refuses a request with no URL or no header map,
	// and closes its body.
	if req.URL == nil || req.Header == nil {
		return t.base.RoundTrip(req) //nolint:wrapcheck // the standard library's error, unchanged
	}

	if t.offline {
		closeBody(req)

		return nil, fmt.Errorf("%w: %s was asked", ErrOffline, req.URL.Host)
	}

	if req.URL.Scheme != https && !t.cleartext {
		closeBody(req)

		return nil, fmt.Errorf("%w: %s://%s", ErrCleartext, req.URL.Scheme, req.URL.Host)
	}

	// A wait for the server is cut short by cancelling the request, which
	// is what unblocks a transport waiting on a connection gone quiet.
	ctx, cancel := context.WithCancelCause(req.Context())

	awaited, shaken := await(cancel, t.stall), &handshakes{}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: shaken.done,
		WroteRequest:     awaited.sent,
	})

	resp, err := t.base.RoundTrip(t.outgoing(ctx, req, awaited))

	awaited.answered()

	if err != nil {
		cancel(nil)

		// Whatever the transport made of the cancelled request: over HTTP/2
		// that is the context's error, of a context that is not the
		// caller's.
		if errors.Is(context.Cause(ctx), ErrStalled) {
			return nil, awaited.stalled()
		}

		return nil, shaken.refused(err)
	}

	// The copy's context ends with the body: the caller's own request is the
	// one it gets back.
	resp.Request = req

	switch stream, switched := resp.Body.(io.ReadWriteCloser); {
	case switched && resp.StatusCode == http.StatusSwitchingProtocols:
		// The connection is the caller's from here, and a quiet connection
		// is not a stalled body.
		resp.Body = &handedOver{ReadWriteCloser: stream, cancel: cancel}
	case t.stall == 0:
		resp.Body = &released{ReadCloser: resp.Body, cancel: cancel}
	default:
		resp.Body = watch(ctx, cancel, resp.Body, t.stall)
	}

	return resp, nil
}

// CloseIdleConnections closes the connections no request is using.
func (t *transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}

// outgoing is req as it is sent: under ctx, with the transport's User-Agent
// when it has none, and its body read through the wait for the server.
func (t *transport) outgoing(ctx context.Context, req *http.Request, awaited *awaiting) *http.Request {
	// A RoundTripper leaves the caller's request as it is. Not Request.Clone:
	// it copies Trailer, which a caller fills while the body is read.
	sent := req.WithContext(ctx)

	if req.Body != nil && req.Body != http.NoBody {
		sent.Body = &sentBody{ReadCloser: req.Body, awaited: awaited}
	}

	// net/http takes the body again from here when it sends a request a
	// second time, on a connection of its pool that turned out closed.
	if req.GetBody != nil {
		sent.GetBody = func() (io.ReadCloser, error) {
			body, err := req.GetBody()
			if err != nil {
				return nil, err //nolint:wrapcheck // the caller's own function, and its error unchanged
			}

			return &sentBody{ReadCloser: body, awaited: awaited}, nil
		}
	}

	if _, named := req.Header["User-Agent"]; t.userAgent != "" && !named {
		sent.Header = req.Header.Clone()
		sent.Header.Set("User-Agent", t.userAgent)
	}

	return sent
}

// closeBody is the part of a RoundTripper's contract that holds on a request
// it refuses: the body is closed all the same.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// handshakes keeps what the last TLS handshake made for one request ended
// in: its error, or nil.
type handshakes struct {
	mu   sync.Mutex
	last error
}

// done is httptrace's TLSHandshakeDone.
func (h *handshakes) done(_ tls.ConnectionState, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.last = err
}

// refused marks err when it is the failure of a handshake made for the
// request, and neither the server's certificate nor the network is its
// cause. A failure is told by where it happened and not by its type: of two
// servers with no TLS 1.3, one says so with an alert, and the other answers
// in TLS 1.2 and it is this side that ends the handshake, with an error that
// has no type.
func (h *handshakes) refused(err error) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// The handshake's error itself, in err's chain: a connection net/http
	// makes for a request may fail while the request travels on another,
	// and ends in an error that is not the handshake's. No error has the
	// nil of a handshake that worked in its chain.
	if errors.Is(err, h.last) && !untrusted(h.last) && !ofTheNetwork(h.last) {
		return fmt.Errorf("%w: %w", ErrHandshakeRefused, err)
	}

	return err
}

func untrusted(err error) bool {
	_, found := errors.AsType[*tls.CertificateVerificationError](err)

	return found
}

// ofTheNetwork reports a handshake that the connection ended, or time did,
// and neither side's TLS: a connection closed or reset, a timeout.
func ofTheNetwork(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	if timed, found := errors.AsType[net.Error](err); found && timed.Timeout() {
		return true
	}

	// crypto/tls gives an alert, received or sent, as an OpError of its own
	// two operations; every other one is the connection's.
	failed, found := errors.AsType[*net.OpError](err)

	return found && failed.Op != "remote error" && failed.Op != "local error"
}

// awaiting fails a request the server leaves waiting for longer than limit:
// for it to take the part of the request's body that was just read, then for
// its response to begin. A limit of zero waits for ever.
type awaiting struct {
	limit time.Duration

	mu    sync.Mutex
	timer *time.Timer
	// whole is set once the request is written whole.
	whole bool
	// over is set once RoundTrip has its answer: net/http may still be
	// writing the request then, and what it reports is no longer waited on.
	over bool
}

func await(cancel context.CancelCauseFunc, limit time.Duration) *awaiting {
	timer := time.AfterFunc(time.Duration(math.MaxInt64), func() { cancel(ErrStalled) })
	timer.Stop()

	return &awaiting{limit: limit, timer: timer}
}

// arm starts the wait, or starts it again: the next move is the server's.
func (a *awaiting) arm() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.limit != 0 && !a.over {
		a.timer.Reset(a.limit)
	}
}

// hold suspends the wait: the next move is the caller's.
func (a *awaiting) hold() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.timer.Stop()
}

// sent is httptrace's WroteRequest: the request is written, or could not be,
// and the wait for the response starts.
func (a *awaiting) sent(written httptrace.WroteRequestInfo) {
	a.mu.Lock()
	a.whole = written.Err == nil
	a.mu.Unlock()

	a.arm()
}

// stalled is the error of a request the wait has ended.
func (a *awaiting) stalled() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.whole {
		return fmt.Errorf("%w: the request was sent, and no response began", ErrStalled)
	}

	return fmt.Errorf("%w: the server stopped taking the request", ErrStalled)
}

// sentBody is a request's body as the transport under this one reads it. The
// time a read takes is the caller's, to produce what it sends, and is not
// counted; the time between two reads is the server's, to take what was
// read, and is.
type sentBody struct {
	io.ReadCloser

	awaited *awaiting
}

func (b *sentBody) Read(into []byte) (int, error) {
	b.awaited.hold()

	read, err := b.ReadCloser.Read(into)

	b.awaited.arm()

	return read, err //nolint:wrapcheck // the caller's own body, and its error unchanged
}

// answered ends the wait: the response began, or the request failed.
func (a *awaiting) answered() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.over = true
	a.timer.Stop()
}

// watchedBody fails a read that waits longer than limit for a byte. The time
// a caller takes between two reads is its own, and is not counted.
type watchedBody struct {
	// A released body, which lets go of ctx.
	io.ReadCloser

	limit  time.Duration
	timer  *time.Timer
	ctx    context.Context //nolint:containedctx // the request's, kept to read why a read failed
	closed atomic.Bool
}

// watch wraps body. The timer is made here, stopped, and the field never
// written again: a Close from another goroutine is how a caller gives up on
// a read that blocks, and it reads the field while Read arms the timer.
func watch(ctx context.Context, cancel context.CancelCauseFunc, body io.ReadCloser, limit time.Duration) *watchedBody {
	timer := time.AfterFunc(time.Duration(math.MaxInt64), func() { cancel(ErrStalled) })
	timer.Stop()

	return &watchedBody{ReadCloser: &released{ReadCloser: body, cancel: cancel}, limit: limit, timer: timer, ctx: ctx}
}

func (b *watchedBody) Read(buf []byte) (int, error) {
	b.timer.Reset(b.limit)

	read, err := b.ReadCloser.Read(buf)

	b.timer.Stop()

	// A body whose end arrived is whole, whatever the timer did meanwhile.
	if err == nil || errors.Is(err, io.EOF) {
		return read, err //nolint:wrapcheck // the body's own error, unchanged
	}

	// Once the watch has fired, a read fails with ErrStalled and nothing
	// else, whatever the body says: over HTTP/2 that is the error of the
	// context cancelled, which is this transport's own and no context of
	// the caller's, and over HTTP/1 a second read finds a closed connection.
	// A body the caller has closed says so itself. The cause read here is
	// the first one given: the release at a read's error comes after it.
	if !b.closed.Load() && errors.Is(context.Cause(b.ctx), ErrStalled) {
		return read, ErrStalled
	}

	return read, err //nolint:wrapcheck // the body's own error, unchanged
}

func (b *watchedBody) Close() error {
	b.closed.Store(true)
	b.timer.Stop()

	return b.ReadCloser.Close() //nolint:wrapcheck // the body's own error, unchanged
}

// released is a body that releases the request's context at its end, as
// net/http's transport releases its own, or when it is closed.
type released struct {
	io.ReadCloser

	cancel context.CancelCauseFunc
}

func (r *released) Read(buf []byte) (int, error) {
	read, err := r.ReadCloser.Read(buf)
	if err != nil {
		r.cancel(nil)
	}

	return read, err //nolint:wrapcheck // the body's own error, unchanged
}

func (r *released) Close() error {
	err := r.ReadCloser.Close()

	r.cancel(nil)

	return err //nolint:wrapcheck // the body's own error, unchanged
}

// handedOver is the connection a protocol switch gave the caller, which
// releases the request's context when closed.
type handedOver struct {
	io.ReadWriteCloser

	cancel context.CancelCauseFunc
}

func (h *handedOver) Close() error {
	err := h.ReadWriteCloser.Close()

	h.cancel(nil)

	return err //nolint:wrapcheck // the body's own error, unchanged
}

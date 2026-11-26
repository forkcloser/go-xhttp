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
	"time"
)

// https is the one scheme the baseline sends, and a credential travels.
const https = "https"

// The timeouts and the pool of every transport.
const (
	dialTimeout           = 30 * time.Second
	dialKeepAlive         = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
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
	stall     time.Duration // zero: a read of a body waits for ever
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
		stall = DefaultStallTimeout
	}

	return &transport{
		base: &http.Transport{
			Proxy:                 proxy,
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig(config),
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
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

	// A body's read is cut short by cancelling the request, the one thing
	// that unblocks a read on a connection gone quiet.
	ctx, cancel := context.WithCancelCause(req.Context())

	// A RoundTripper leaves the caller's request as it is. Not Request.Clone:
	// it copies Trailer, which a caller fills while the body is read.
	sent := req.WithContext(ctx)

	if _, named := req.Header["User-Agent"]; t.userAgent != "" && !named {
		sent.Header = req.Header.Clone()
		sent.Header.Set("User-Agent", t.userAgent)
	}

	resp, err := t.base.RoundTrip(sent)
	if err != nil {
		cancel(nil)

		return nil, refused(err)
	}

	// The copy's context ends when the body is closed: the caller's own
	// request is the one it gets back.
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

// closeBody is the part of a RoundTripper's contract that holds on a request
// it refuses: the body is closed all the same.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// refused marks a TLS alert from the server, which reaches here as a
// net.OpError of this operation: the alert type behind it is not exported.
func refused(err error) error {
	if opErr, ok := errors.AsType[*net.OpError](err); ok && opErr.Op == "remote error" {
		return fmt.Errorf("%w: %w", ErrHandshakeRefused, err)
	}

	return err
}

// watchedBody fails a read that waits longer than limit for a byte. The time
// a caller takes between two reads is its own, and is not counted.
type watchedBody struct {
	io.ReadCloser

	limit  time.Duration
	timer  *time.Timer
	ctx    context.Context //nolint:containedctx // the request's, kept to read why a read failed
	cancel context.CancelCauseFunc
}

// watch wraps body. The timer is made here, stopped, and the field never
// written again: a Close from another goroutine is how a caller gives up on
// a read that blocks, and it reads the field while Read arms the timer.
func watch(ctx context.Context, cancel context.CancelCauseFunc, body io.ReadCloser, limit time.Duration) *watchedBody {
	timer := time.AfterFunc(time.Duration(math.MaxInt64), func() { cancel(ErrStalled) })
	timer.Stop()

	return &watchedBody{ReadCloser: body, limit: limit, timer: timer, ctx: ctx, cancel: cancel}
}

func (b *watchedBody) Read(buf []byte) (int, error) {
	b.timer.Reset(b.limit)

	read, err := b.ReadCloser.Read(buf)

	b.timer.Stop()

	// A body whose end arrived is whole, whatever the timer did meanwhile.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, ErrStalled) {
		return read, err //nolint:wrapcheck // the body's own error, unchanged
	}

	if errors.Is(context.Cause(b.ctx), ErrStalled) {
		return read, fmt.Errorf("%w: %w", ErrStalled, err)
	}

	return read, err //nolint:wrapcheck // the body's own error, unchanged
}

func (b *watchedBody) Close() error {
	b.timer.Stop()

	err := b.ReadCloser.Close()

	b.cancel(nil)

	return err //nolint:wrapcheck // the body's own error, unchanged
}

// released is a body nothing watches, which releases the request's context
// when closed.
type released struct {
	io.ReadCloser

	cancel context.CancelCauseFunc
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

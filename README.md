# xhttp

The client side of `net/http` under a posture. `xhttp` returns the standard
library's own types, an `*http.Client` and an `http.RoundTripper`, built from
a `Config` whose zero value is the strictest setting. Whatever is weaker is
asked for by name. It keeps no state of its own, so a library uses it as a
program does.

```go
import (
	"github.com/forkcloser/go-xhttp"
	"github.com/forkcloser/go-xhttp/retry"
)

client := xhttp.NewClient(xhttp.Config{})
client.Transport = retry.NewTransport(client.Transport, retry.Options{Retries: 3})
```

## The baseline

| Protection | The zero `Config` | Asked for by name |
|---|---|---|
| Scheme | https only, `ErrCleartext` otherwise | `Config.Cleartext` |
| Proxy | the environment's; credentials for it over https only, `ErrCleartext` otherwise | `Config.Proxy`, `Config.Cleartext` |
| Trust | the system's roots | `Config.Roots`; or `Config.Pin`, one server by its certificate's fingerprint and no other host, `ErrPinMismatch` otherwise |
| TLS | `HybridOnly`: TLS 1.3, post-quantum hybrid key exchanges only | `Config.TLS`: `Classical`, `Legacy`, for the whole transport |
| Silent server | a request the server stops taking for a minute, a response that has not begun a minute after the request was sent, or a read of its body that waits a minute for a byte, fails with `ErrStalled` | `Config.StallTimeout`, negative to wait for ever |
| Redirects | none from https to anything else, under any client; at most 10 under `NewClient` | a client of your own, for another limit |
| Credential | sent over https to the hosts it names, and to no other, nor after a redirect from a host it does not name | the hosts given to `NewCredential` |
| Offline | off | `Config.Offline` |

A transport has one TLS level, for every connection it makes: a
program that reaches hosts at two levels makes two transports. A TLS
handshake that fails for another reason than the server's certificate or the
network is `ErrHandshakeRefused`, the one sentinel to test before naming a
weaker level for that server.

## One server, by its certificate

A server no authority vouches for, a device with a certificate of its own
making, is trusted by the fingerprint of that certificate and by nothing
else:

```go
pin, err := xhttp.NewPin("192.0.2.10:8443", fingerprint)
if err != nil {
	return err
}

client := xhttp.NewClient(xhttp.Config{Pin: pin})
```

The fingerprint is the SHA-256 of the certificate the server presents, as 64
hexadecimal digits or as `openssl x509 -noout -fingerprint -sha256` prints
it. Who signed the certificate, the name it bears and its dates are not
consulted. A transport that has a pin is that server's alone: a request for
another host or another port is not sent, it takes no proxy, and a server
that presents another certificate is `ErrPinMismatch`, which holds the
fingerprint presented. A certificate that is renewed is another certificate,
and another pin.

## Retries

`retry.NewTransport` wraps any `http.RoundTripper`. It sends a request again
after a failure or a 408, 429, 500, 502, 503 or 504, when the request is
idempotent (GET, HEAD, OPTIONS, TRACE, PUT, DELETE, or one with an
`Idempotency-Key`) and its body can be read again. It waits with a doubling,
jittered backoff, obeys `Retry-After` up to `Options.MaxBackoff`, and returns
the last attempt's response whatever its status: the status is the caller's
to read, as with any `http.RoundTripper`.

The package docs hold the whole contract: `go doc github.com/forkcloser/go-xhttp`
and `go doc github.com/forkcloser/go-xhttp/retry`.

## Developing

Every workflow runs through `just`: `just lint`, `just test`, `just fix`;
`just --list` shows the rest. The contributor rules are in `AGENTS.md`.

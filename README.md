# xhttp

The client side of `net/http` under a posture. `xhttp` returns the standard
library's own types, an `*http.Client` and an `http.RoundTripper`, built from
a `Config` whose zero value is the strictest setting. Whatever is weaker is
asked for by name. Nothing reads or writes a global, so a library uses it as
a program does.

```go
import (
	"github.com/forkcloser/xhttp"
	"github.com/forkcloser/xhttp/retry"
)

client := xhttp.NewClient(xhttp.Config{})
client.Transport = retry.NewTransport(client.Transport, retry.Options{Retries: 3})
```

## The baseline

| Protection | The zero `Config` | Asked for by name |
|---|---|---|
| Scheme | https only, `ErrCleartext` otherwise | `Config.Cleartext` |
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

## Retries

`retry.NewTransport` wraps any `http.RoundTripper`. It sends a request again
after a failure or a 429, 500, 502, 503 or 504, when the request is idempotent
(GET, HEAD, OPTIONS, TRACE, PUT, DELETE, or one with an `Idempotency-Key`) and
its body can be read again. It waits with a doubling, jittered backoff, obeys
`Retry-After` up to `Options.MaxBackoff`, and returns the last attempt's
response whatever its status: the status is the caller's to read, as with any
`http.RoundTripper`.

The package docs hold the whole contract: `go doc github.com/forkcloser/xhttp`
and `go doc github.com/forkcloser/xhttp/retry`.

## Developing

Every workflow runs through `just`: `just lint`, `just test`, `just fix`;
`just --list` shows the rest. The contributor rules are in `AGENTS.md`.

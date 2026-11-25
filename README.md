# xhttp

The client side of `net/http` under a posture. `xhttp` returns the standard
library's own types, an `*http.Client` and an `http.RoundTripper`, built from
a `Config` whose zero value is the strictest setting. Whatever is weaker is
asked for by name. Nothing reads or writes a global, so a library uses it as
a program does.

```go
import "github.com/forkcloser/xhttp"

client := xhttp.NewClient(xhttp.Config{})
```

## The baseline

| Protection | The zero `Config` | Asked for by name |
|---|---|---|
| Scheme | https only, `ErrCleartext` otherwise | `Config.Cleartext` |
| Key exchange | `HybridOnly`: TLS 1.3, post-quantum hybrids only | `Classical`, `Legacy`, for the whole transport |
| Stalled body | a read that waits a minute for a byte fails with `ErrStalled` | `Config.StallTimeout`, negative to wait for ever |
| Redirects | at most 10, none from https to anything else | `Redirects(limit)` on a client of your own |
| Credential | sent over https to the hosts it names, and to no other | `Credential.Hosts` |
| Offline | off | `Config.Offline` |

A transport has one key exchange level, for every connection it makes: a
program that reaches hosts at two levels makes two transports. A server that
ends the TLS handshake with an alert is `ErrHandshakeRefused`, the one
sentinel to test before naming a weaker level for that server.

The package doc holds the whole contract: `go doc github.com/forkcloser/xhttp`.

## Developing

Every workflow runs through `just`: `just lint`, `just test`, `just fix`;
`just --list` shows the rest. The contributor rules are in `AGENTS.md`.

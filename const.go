package xhttp

// KeyExchange is what a transport's connections may agree their keys with,
// and under which TLS versions. The zero value is the strictest, and each one
// after it gives something up.
type KeyExchange int

const (
	// HybridOnly is TLS 1.3 with a post-quantum hybrid key exchange, and
	// nothing else.
	HybridOnly KeyExchange = iota
	// Classical is TLS 1.3 with any key exchange Go offers, the classical
	// ones included, for a server that has no hybrid.
	Classical
	// Legacy is TLS as Go defaults it, 1.2 included, for a server that has
	// no TLS 1.3.
	Legacy
)

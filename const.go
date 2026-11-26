package xhttp

// TLSLevel is what a transport's connections accept of TLS: which versions,
// and which key exchanges. The zero value is the strictest, and each one
// after it gives something up.
type TLSLevel int

const (
	// HybridOnly is TLS 1.3 with a post-quantum hybrid key exchange, and
	// nothing else.
	HybridOnly TLSLevel = iota
	// Classical is TLS 1.3 with any key exchange Go offers, the classical
	// ones included, for a server that has no hybrid.
	Classical
	// Legacy is TLS as Go defaults it, 1.2 included, for a server that has
	// no TLS 1.3.
	Legacy
)

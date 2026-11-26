package xhttp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
)

// Pin is a server trusted by the fingerprint of its certificate, and by
// nothing else, made by [NewPin]. A transport that has one ([Config.Pin])
// completes a TLS handshake only with a server that presents that very
// certificate, whoever signed it, whatever name it bears and whenever it
// expires, and that proves it holds the certificate's key, as every TLS
// handshake has a server do. Such a transport reaches no host but the pinned
// one, so that the holder of that key is never taken for another server.
// The zero Pin is none.
type Pin struct {
	host host
	sum  [sha256.Size]byte
	set  bool
}

var errNoFingerprint = errors.New("not the SHA-256 of a certificate in hexadecimal")

// A fingerprint as openssl prints it: a pair of digits for each byte, and a
// colon between two pairs.
const paired = sha256.Size*3 - 1

// NewPin returns the pin of server to the certificate whose SHA-256 is
// fingerprint.
//
// The server is written as a credential's host is ([NewCredential]): in
// ASCII, a name or an IPv4 address, or an IPv6 address in brackets, alone for
// the https port or followed by a colon and a port. The fingerprint is the
// SHA-256 of the certificate the server presents, in hexadecimal: 64 digits,
// or 32 pairs of them with a colon between two.
//
// Anything else is [ErrPin].
func NewPin(server, fingerprint string) (Pin, error) {
	parsed, err := parseHost(server)
	if err != nil {
		return Pin{}, fmt.Errorf("%w: host %q: %w", ErrPin, server, err)
	}

	digits := []byte(fingerprint)

	if len(fingerprint) == paired {
		digits = digits[:0]

		for at := range len(fingerprint) {
			switch {
			case at%3 != 2:
				digits = append(digits, fingerprint[at])
			case fingerprint[at] != ':':
				return Pin{}, fmt.Errorf("%w: fingerprint %q: %w", ErrPin, fingerprint, errNoFingerprint)
			}
		}
	}

	made := Pin{host: parsed, set: true}

	// The length first: Decode takes any even number of digits, and panics
	// on more than there is room for.
	if len(digits) != hex.EncodedLen(len(made.sum)) {
		return Pin{}, fmt.Errorf("%w: fingerprint %q: %w", ErrPin, fingerprint, errNoFingerprint)
	}

	if _, err = hex.Decode(made.sum[:], digits); err != nil {
		return Pin{}, fmt.Errorf("%w: fingerprint %q: %w", ErrPin, fingerprint, errNoFingerprint)
	}

	return made, nil
}

// String is the host and the fingerprint, neither of which is a secret.
func (p Pin) String() string {
	if !p.set {
		return "no pin"
	}

	return fmt.Sprintf("%s pinned to %x", p.host, p.sum)
}

// verify is the tls.Config.VerifyConnection of a pinned transport, which
// crypto/tls calls for every handshake, a resumed one included. On the
// client's side the peer's certificates are never empty, and the first is
// the server's own.
func (p Pin) verify(state tls.ConnectionState) error {
	if presented := sha256.Sum256(state.PeerCertificates[0].Raw); presented != p.sum {
		return fmt.Errorf("%w: %s is pinned to %x, and presented %x", ErrPinMismatch, p.host, p.sum, presented)
	}

	return nil
}

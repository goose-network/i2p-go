package noise

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Public derives the public key for a 32-byte private scalar. Exposed
// for callers that need to derive their own static key's public half
// (e.g. the router publishing the NTCP2 "s" address option).
// Reference: Curve25519DHState (getPublicKey).
func Public(priv []byte) ([]byte, error) { return x25519Public(priv) }

// x25519Public derives the public key for a 32-byte private scalar.
// Reference: Curve25519DHState (getPublicKey).
func x25519Public(priv []byte) ([]byte, error) {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("noise: x25519 public: %w", err)
	}
	return pub, nil
}

// x25519DH computes the raw X25519 shared secret. An all-zero output
// (low-order point) is rejected. Reference: Curve25519DHState.calculate.
func x25519DH(priv, pub []byte) ([]byte, error) {
	if len(priv) != 32 || len(pub) != 32 {
		return nil, fmt.Errorf("noise: x25519 bad key lengths %d/%d", len(priv), len(pub))
	}
	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("noise: x25519 dh: %w", err)
	}
	if allZero(shared) {
		return nil, fmt.Errorf("noise: x25519 all-zero shared secret")
	}
	return shared, nil
}

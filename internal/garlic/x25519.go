package garlic

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// x25519Public derives the public key for a 32-byte private scalar.
func x25519Public(priv []byte) ([]byte, error) {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("garlic: x25519 public: %w", err)
	}
	return pub, nil
}

// x25519DH computes the raw X25519 shared secret, rejecting low-order
// points.
func x25519DH(priv, pub []byte) ([]byte, error) {
	if len(priv) != 32 || len(pub) != 32 {
		return nil, fmt.Errorf("garlic: x25519 bad key lengths %d/%d", len(priv), len(pub))
	}
	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("garlic: x25519 dh: %w", err)
	}
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("garlic: x25519 all-zero shared secret")
	}
	return shared, nil
}

// GenerateX25519Keypair returns a random X25519 keypair.
func GenerateX25519Keypair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return
	}
	pub, err = x25519Public(priv)
	return
}

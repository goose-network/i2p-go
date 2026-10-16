package reseed

import (
	"crypto"
	"crypto/ed25519"
	"embed"
	"testing"
)

//go:embed certs/*.crt
var certFS embed.FS

// TrustedKeys returns the bundled reseed signer keys.
func TrustedKeys(t *testing.T) map[string]crypto.PublicKey {
	t.Helper()
	keys := map[string]crypto.PublicKey{}
	entries, err := certFS.ReadDir("certs")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := certFS.ReadFile("certs/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		m, err := ParseCertsPEM(b)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range m {
			keys[k] = v
		}
	}
	return keys
}

var _ = ed25519.PublicKey{}

package reseed

import (
	"testing"
)

// TestTrustedKeysLoad checks the bundled reseed signer certificates
// parse into usable public keys.
func TestTrustedKeysLoad(t *testing.T) {
	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 10 {
		t.Fatalf("expected at least 10 signer keys, got %d", len(keys))
	}
	for name, key := range keys {
		if key == nil {
			t.Fatalf("nil key for signer %q", name)
		}
	}
}

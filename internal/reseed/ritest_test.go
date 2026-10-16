package reseed

import (
	"bytes"
	"os"
	"testing"

	"github.com/goose-network/i2p-go/internal/data"
)

// TestRIRoundTripAndVerify re-parses and verifies every router info in
// the real bundle, checking byte-exact round-trip and Ed25519
// signature validity.
func TestRIRoundTripAndVerify(t *testing.T) {
	b, err := os.ReadFile("/tmp/i2p-research/k.su3")
	if err != nil {
		t.Skip("no real su3 bundle available")
	}
	s, err := ParseSU3(b)
	if err != nil {
		t.Fatal(err)
	}
	ris, err := s.ExtractRouterInfos()
	if err != nil {
		t.Fatal(err)
	}
	nVerified, nExact := 0, 0
	for _, ri := range ris {
		if err := ri.Verify(); err != nil {
			t.Errorf("router %s: %v", ri.NetDBFileName()[:12], err)
		} else {
			nVerified++
		}
		re, err := data.ReadRouterInfo(ri.Bytes(), false)
		if err != nil {
			t.Errorf("reparse %s: %v", ri.NetDBFileName()[:12], err)
			continue
		}
		if !bytes.Equal(re.Bytes(), ri.Bytes()) {
			t.Errorf("round-trip mismatch for %s (%d vs %d bytes)", ri.NetDBFileName()[:12], len(re.Bytes()), len(ri.Bytes()))
			continue
		}
		nExact++
	}
	t.Logf("verified %d/%d signatures, %d/%d byte-exact round-trips", nVerified, len(ris), nExact, len(ris))
}

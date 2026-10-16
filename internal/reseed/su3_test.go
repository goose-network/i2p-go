package reseed

import (
	"os"
	"testing"

	"crypto/ed25519"
)

type ed25519PublicKey = ed25519.PublicKey

// TestParseRealSU3 parses the real reseed bundle fetched from
// reseed.kiota.ch (downloaded to /tmp/i2p-research/k.su3 when the
// network is reachable). It is skipped when the file is absent.
func TestParseRealSU3(t *testing.T) {
	b, err := os.ReadFile("/tmp/i2p-research/k.su3")
	if err != nil {
		t.Skip("no real su3 bundle available")
	}
	s, err := ParseSU3(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signer=%q version=%q content=%d bytes sigType=%d fileType=%d contentType=%d",
		s.Signer, s.Version, s.ContentLength, s.SigType, s.FileType, s.ContentType)
	if s.Signer == "" {
		t.Fatal("empty signer")
	}
	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(keys); err != nil {
		t.Fatal(err)
	}
	ris, err := s.ExtractRouterInfos()
	if err != nil {
		t.Fatal(err)
	}
	if len(ris) == 0 {
		t.Fatal("no router infos extracted")
	}
	t.Logf("extracted %d router infos", len(ris))
	for i, ri := range ris {
		if i > 3 {
			break
		}
		hash := ri.RouterHash()
		t.Logf("  router %s published=%v sigType=%d encType=%d addrs=%d",
			hash.ToI2PBase64()[:12], ri.Published, ri.Identity.SigType, ri.Identity.EncType, len(ri.Addresses))
	}
}

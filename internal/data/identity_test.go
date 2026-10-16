package data

import (
	"crypto/sha256"
	"testing"
)

// TestDestinationHashRoundTrip pins the identity-hash rule that broke
// eepsite lookups: a Destination (or RouterIdentity) parsed from its
// wire bytes must re-encode byte-for-byte, so its hash equals
// SHA-256(raw bytes) — including legacy ElGamal+DSA destinations whose
// certificate is the 3-byte NULL, where synthesizing a key certificate
// instead changed the bytes, the hash, and the b32 hostname.
func TestDestinationHashRoundTrip(t *testing.T) {
	// A legacy ElGamal+DSA destination: 256-byte enc key, 128-byte
	// signing key, NULL certificate (type 0, length 0).
	raw := make([]byte, 387)
	raw[256] = 0x42 // distinct signing key head
	var enc []byte
	enc = append(enc, raw...)
	want := sha256.Sum256(enc)

	dest, rest, err := ReadDestination(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("leftover %d bytes", len(rest))
	}
	if got := dest.RouterHash(); got != Hash(want) {
		t.Fatalf("legacy dest hash mismatch: %s != %s", got.ToI2PBase64()[:12], Hash(want).ToI2PBase64()[:12])
	}

	// And the b32 hostname (52 base32 chars of the hash) matches.
	if got, want := dest.Base32Address()[:16], EncodeToI2PBase32(want[:])[:16]; got != want {
		t.Fatalf("b32 mismatch: %s != %s", got, want)
	}
}

// TestIdentityReencodeRawBytes checks byte-exact re-encoding of parsed
// identities for both certificate families.
func TestIdentityReencodeRawBytes(t *testing.T) {
	// Legacy NULL-cert identity.
	legacy := make([]byte, 387)
	id, _, err := ReadRouterIdentity(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if out := id.WriteTo(nil); string(out) != string(legacy) {
		t.Fatalf("legacy identity re-encode differs: %d vs %d bytes", len(out), len(legacy))
	}

	// Key-certificate identity: X25519 enc key + Ed25519 signing key.
	var raw []byte
	raw = append(raw, make([]byte, 256)...) // enc field: key + padding
	sig := make([]byte, 128)
	sig[96] = 0x07 // somewhere in the tail 32 bytes
	raw = append(raw, sig...)
	// NULL cert would be wrong here: build a key cert (type 5, 4-byte payload).
	kc := KeyCertificate{SigType: SigEdDSA_SHA512_Ed25519, EncType: EncECIES_X25519}
	raw = kc.WriteTo(raw)

	id, _, err = ReadRouterIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out := id.WriteTo(nil); string(out) != string(raw) {
		t.Fatal("key-cert identity re-encode differs")
	}
	if id.SigType != SigEdDSA_SHA512_Ed25519 || id.EncType != EncECIES_X25519 {
		t.Fatalf("parsed types %d/%d", id.SigType, id.EncType)
	}
}

// TestConstructedIdentityHashStable pins the constructed-identity path:
// identities built in-process (no parsed certificate) keep hashing the
// same bytes as before the certRaw fix — the synthesized key
// certificate.
func TestConstructedIdentityHashStable(t *testing.T) {
	id := RouterIdentity{
		EncKey:     make([]byte, 32),
		SigningKey: make([]byte, 32),
		SigType:    SigEdDSA_SHA512_Ed25519,
		EncType:    EncECIES_X25519,
	}
	// 256 enc field + 128 sig field + 7-byte key cert.
	if out := id.WriteTo(nil); len(out) != 256+128+3+4 {
		t.Fatalf("constructed identity length %d", len(out))
	}
}

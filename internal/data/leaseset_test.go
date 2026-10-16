package data

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// buildDest builds a minimal X25519/Ed25519 destination.
func buildDest(t *testing.T) (Destination, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := Destination{
		EncKey:     bytes.Repeat([]byte{0x22}, 32),
		SigningKey: priv[32:],
		SigType:    SigEdDSA_SHA512_Ed25519,
		EncType:    EncECIES_X25519,
	}
	return d, priv
}

func TestLeaseSet2RoundTrip(t *testing.T) {
	dest, priv := buildDest(t)
	ls := &LeaseSet2{
		Destination: dest,
		Published:   time.Unix(1700000000, 0),
		Expires:     time.Unix(1700000000, 0).Add(10 * time.Minute),
		Options:     map[string]string{"i2p.streaming.initialDelay": "20"},
		EncryptionKeys: []PublicKey{
			{EncType: EncECIES_X25519, Key: bytes.Repeat([]byte{0x33}, 32)},
		},
		Leases: []Lease{
			{Gateway: Hash{1}, TunnelID: 77, End: time.Unix(1700000600, 0)},
			{Gateway: Hash{2}, TunnelID: 78, End: time.Unix(1700000600, 0)},
		},
	}
	if err := ls.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw := ls.Bytes()
	got, err := ReadLeaseSet2(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Destination.RouterHash().Equal(ls.Destination.RouterHash()) {
		t.Fatal("destination mismatch")
	}
	if !got.Expires.Equal(ls.Expires) || got.Flags != ls.Flags {
		t.Fatalf("header mismatch: %+v", got)
	}
	if len(got.Leases) != 2 || got.Leases[1].TunnelID != 78 {
		t.Fatalf("lease mismatch: %+v", got.Leases)
	}
	if len(got.EncryptionKeys) != 1 || !bytes.Equal(got.EncryptionKeys[0].Key, ls.EncryptionKeys[0].Key) {
		t.Fatal("encryption key mismatch")
	}
	if got.Destination.Base32Address() == "" || len(got.Destination.Base32Address()) != 60 {
		t.Fatalf("b32 address %q", got.Destination.Base32Address())
	}
	// Tamper.
	raw[len(raw)-1] ^= 1
	if _, err := ReadLeaseSet2(raw, true); err == nil {
		t.Fatal("tampered LS2 accepted")
	}
}

func TestLeaseSet2Offline(t *testing.T) {
	dest, priv := buildDest(t)
	// Transient signing keypair.
	_, tpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ls := &LeaseSet2{
		Destination:      dest,
		Published:        time.Now(),
		Expires:          time.Now().Add(10 * time.Minute),
		Flags:            LS2FlagOfflineKeys,
		TransientExpires: time.Now().Add(time.Hour),
		TransientSigType: SigEdDSA_SHA512_Ed25519,
		TransientSPK:     tpriv[32:],
		EncryptionKeys: []PublicKey{
			{EncType: EncECIES_X25519, Key: bytes.Repeat([]byte{0x44}, 32)},
		},
	}
	// Offline signature by the destination SPK over the offline block.
	ls.OfflineSignature = ed25519.Sign(priv, ls.offlineBlockBytes())
	if err := ls.Sign(tpriv); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLeaseSet2(ls.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags&LS2FlagOfflineKeys == 0 {
		t.Fatal("offline flag lost")
	}
	if got.TransientExpires.Unix() != ls.TransientExpires.Unix() {
		t.Fatalf("transient expiry mismatch: %v vs %v", got.TransientExpires, ls.TransientExpires)
	}
}

func TestLeaseSet1RoundTrip(t *testing.T) {
	dest, priv := buildDest(t)
	ls := &LeaseSet{
		Destination:   dest,
		EncryptionKey: bytes.Repeat([]byte{0x55}, 32),
		SigningKey:    dest.SigningKey,
		Leases: []Lease1{
			{Gateway: Hash{9}, TunnelID: 1234, End: time.UnixMilli(1700000000000)},
		},
	}
	var buf []byte
	buf = ls.Destination.WriteTo(buf)
	buf = append(buf, ls.EncryptionKey...)
	buf = append(buf, ls.SigningKey...)
	buf = append(buf, byte(len(ls.Leases)))
	for _, l := range ls.Leases {
		buf = append(buf, l.Gateway[:]...)
		buf = append(buf, byte(l.TunnelID>>24), byte(l.TunnelID>>16), byte(l.TunnelID>>8), byte(l.TunnelID))
		buf = append(buf, AppendDate(l.End)...)
	}
	ls.Signature = ed25519.Sign(priv, buf)
	raw := append(buf, ls.Signature...)
	got, err := ReadLeaseSet(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leases[0].TunnelID != 1234 || !got.Leases[0].End.Equal(ls.Leases[0].End) {
		t.Fatalf("lease mismatch: %+v", got.Leases)
	}
}

// Hash.Equal is used above; make sure it exists in a sane form.
func TestHashEqual(t *testing.T) {
	var a, b Hash
	a[0] = 1
	if a.Equal(b) {
		t.Fatal("different hashes equal")
	}
	b[0] = 1
	if !a.Equal(b) {
		t.Fatal("same hashes unequal")
	}
}

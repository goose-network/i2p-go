package noise

import (
	"bytes"
	"testing"
)

// TestXKHandshakeRoundTrip runs a complete XK handshake between an
// initiator and a responder, checking that both derive identical
// transport keys and that the responder learns the initiator's static
// key.
func TestXKHandshakeRoundTrip(t *testing.T) {
	const protocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

	alice, err := NewHandshakeState(protocolName, XK, true, nil, bobStaticPub(t))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshakeState(protocolName, XK, false, bobStaticPriv(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(alice.RemoteStatic(), bobStaticPub(t)) {
		t.Fatal("alice does not know bob's static key")
	}

	// -> e es
	msg1, err := alice.WriteMessage([]byte("options1-payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 32 (e) + payload + 16 (mac)
	if len(msg1) != 32+len("options1-payload")+16 {
		t.Fatalf("msg1 length %d", len(msg1))
	}
	p1, err := bob.ReadMessage(msg1)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1) != "options1-payload" {
		t.Fatalf("msg1 payload %q", p1)
	}

	// <- e ee
	msg2, err := bob.WriteMessage([]byte("options2-payload"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := alice.ReadMessage(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if string(p2) != "options2-payload" {
		t.Fatalf("msg2 payload %q", p2)
	}

	// -> s, se
	msg3, err := alice.WriteMessage([]byte("msg3-p2-payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 48 (s + mac) + payload + 16
	if len(msg3) != 48+len("msg3-p2-payload")+16 {
		t.Fatalf("msg3 length %d", len(msg3))
	}
	p3, err := bob.ReadMessage(msg3)
	if err != nil {
		t.Fatal(err)
	}
	if string(p3) != "msg3-p2-payload" {
		t.Fatalf("msg3 payload %q", p3)
	}

	// Bob now knows Alice's static key.
	if !bytes.Equal(bob.RemoteStatic(), alice.LocalStaticPublic()) {
		t.Fatal("bob did not learn alice's static key")
	}

	// Split.
	aSend, aRecv, err := alice.Split()
	if err != nil {
		t.Fatal(err)
	}
	bSend, bRecv, err := bob.Split()
	if err != nil {
		t.Fatal(err)
	}

	// Transport keys must agree: Alice sends with k1, Bob receives with k1.
	ct := aSend.Seal(nil, []byte("data-phase-a2b"))
	pt, err := bRecv.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "data-phase-a2b" {
		t.Fatalf("a2b payload %q", pt)
	}
	ct = bSend.Seal(nil, []byte("data-phase-b2a"))
	pt, err = aRecv.Open(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "data-phase-b2a" {
		t.Fatalf("b2a payload %q", pt)
	}

	// Cross-checks: wrong direction must fail.
	if _, err := bSend.Open(nil, ct); err == nil {
		t.Fatal("b2a decrypt with bSend succeeded")
	}
}

// TestTamperedMsg2 verifies authentication of handshake messages.
func TestTamperedMsg2(t *testing.T) {
	const protocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
	alice, err := NewHandshakeState(protocolName, XK, true, nil, bobStaticPub(t))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshakeState(protocolName, XK, false, bobStaticPriv(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := alice.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(msg1); err != nil {
		t.Fatal(err)
	}
	msg2, err := bob.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2[40] ^= 1 // tamper inside the encrypted payload region
	if _, err := alice.ReadMessage(msg2); err == nil {
		t.Fatal("tampered msg2 accepted")
	}
}

var bobPriv = []byte{
	0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x11, 0x13,
	0x15, 0x17, 0x19, 0x1b, 0x1d, 0x1f, 0x23, 0x25,
	0x27, 0x29, 0x2b, 0x2d, 0x2f, 0x31, 0x33, 0x35,
	0x37, 0x39, 0x3b, 0x3d, 0x3f, 0x41, 0x43, 0x45,
}

func bobStaticPriv(t *testing.T) []byte {
	t.Helper()
	priv, pub, err := NewTestKeys()
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	return priv
}

func bobStaticPub(t *testing.T) []byte {
	t.Helper()
	_, pub, err := NewTestKeys()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// NewTestKeys returns a fixed deterministic keypair for tests.
func NewTestKeys() (priv, pub []byte, err error) {
	priv = append([]byte(nil), bobPriv...)
	pub, err = x25519Public(priv)
	return
}

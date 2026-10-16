package garlic

import (
	"testing"
)

// TestGarlicSelfRoundTrip reproduces the live self-connect path: ONE
// manager encrypting to its own public key (our destination dials
// itself for testing).
func TestGarlicSelfRoundTrip(t *testing.T) {
	priv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ns := m.EncryptSession(m.PublicKey(), []*Clove{testClove(t, "self-ns")})
		if ns == nil {
			t.Fatal("nil NS")
		}
		cloves, err := m.DecryptMessage(ns)
		if err != nil {
			t.Fatalf("self decrypt %d: %v", i, err)
		}
		if len(cloves) != 1 || string(cloves[0].Msg.Payload) != "self-ns" {
			t.Fatalf("self cloves %d: %+v", i, cloves)
		}
	}
}

// TestGarlicRetransmitKeepsPriorNS verifies that a retransmitted NS
// does not orphan the earlier handshake: the NSR answering the first
// NS must still decrypt even though a second NS was sent in between.
// This is the racy-but-common connect path — the SYN's first RTO fires
// before the NSR crosses the network back.
func TestGarlicRetransmitKeepsPriorNS(t *testing.T) {
	alicePriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewManager(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewManager(bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	// First NS (the original SYN packet).
	ns1 := alice.EncryptSession(bob.PublicKey(), []*Clove{testClove(t, "ns1")})
	if ns1 == nil {
		t.Fatal("nil NS1")
	}
	// Retransmit: a second NS before any reply (RTO fired). Must not
	// destroy the first handshake's reply-tag set.
	ns2 := alice.EncryptSession(bob.PublicKey(), []*Clove{testClove(t, "ns2")})
	if ns2 == nil {
		t.Fatal("nil NS2")
	}

	// Bob answers the FIRST NS (his reply crossed Alice's retransmit
	// on the wire).
	if _, err := bob.DecryptMessage(ns1); err != nil {
		t.Fatalf("bob decrypt ns1: %v", err)
	}
	bob.mu.Lock()
	var bobSess *Session
	for _, s := range bob.sessions {
		bobSess = s
	}
	bob.mu.Unlock()
	if bobSess == nil {
		t.Fatal("Bob has no session after NS1")
	}
	bobSess.mu.Lock()
	state := bobSess.outNSR.state
	bobSess.mu.Unlock()
	if state == nil {
		t.Fatal("Bob session has no stored handshake state")
	}
	nsr := bob.BuildNSR(state, []*Clove{testClove(t, "reply-to-ns1")})
	if nsr == nil {
		t.Fatal("nil NSR")
	}

	// The NSR for the superseded NS must still decrypt at Alice.
	cloves, err := alice.DecryptMessage(nsr)
	if err != nil {
		t.Fatalf("NSR for prior NS lost: %v", err)
	}
	if len(cloves) != 1 || string(cloves[0].Msg.Payload) != "reply-to-ns1" {
		t.Fatalf("cloves wrong: %+v", cloves)
	}
}

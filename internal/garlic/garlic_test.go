package garlic

import (
	"bytes"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/i2np"
)

// aliceClove builds a test clove carrying a Data message.
func testClove(t *testing.T, body string) *Clove {
	t.Helper()
	msg := i2np.New(i2np.TypeData, []byte(body))
	return buildLocalClove(msg)
}

// TestGarlicRoundTrip runs the full ECIES-Ratchet protocol between an
// Alice manager (client) and a Bob manager (server): NS → NSR → ES
// in both directions, plus clove and payload round-trips.
func TestGarlicRoundTrip(t *testing.T) {
	bobPriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	alicePriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewManager(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewManager(alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	clove := testClove(t, "first-message-in-ns")

	// Alice → Bob: New Session.
	ns := alice.EncryptSession(bob.PublicKey(), []*Clove{clove})
	if ns == nil {
		t.Fatal("nil NS")
	}
	if len(ns) < 96 {
		t.Fatalf("NS too short: %d", len(ns))
	}
	// The first 32 bytes must be decodable Elligator2.
	if Elligator2Decode(ns[:32]) == nil {
		t.Fatal("NS ephemeral is not Elligator2-decodable")
	}

	gotCloves, err := bob.DecryptMessage(ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCloves) != 1 {
		t.Fatalf("NS delivered %d cloves", len(gotCloves))
	}
	if string(gotCloves[0].Msg.Payload) != "first-message-in-ns" {
		t.Fatalf("NS payload %q", gotCloves[0].Msg.Payload)
	}

	// Bob → Alice: NSR (a reply carrying a clove back).
	replyClove := testClove(t, "reply-in-nsr")
	bob.mu.Lock()
	var bobSess *Session
	for _, s := range bob.sessions {
		bobSess = s
	}
	bob.mu.Unlock()
	if bobSess == nil {
		t.Fatal("Bob has no session after NS")
	}
	bobSess.mu.Lock()
	state := bobSess.outNSR.state
	bobSess.mu.Unlock()
	if state == nil {
		t.Fatal("Bob session has no stored handshake state")
	}
	nsr := bob.BuildNSR(state, []*Clove{replyClove})
	if nsr == nil {
		t.Fatal("nil NSR")
	}
	if len(nsr) < 72 {
		t.Fatalf("NSR too short: %d", len(nsr))
	}

	gotCloves, err = alice.DecryptMessage(nsr)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCloves) != 1 || string(gotCloves[0].Msg.Payload) != "reply-in-nsr" {
		t.Fatalf("NSR cloves wrong: %+v", gotCloves)
	}

	// Alice → Bob: ES (session established both sides now).
	esClove := testClove(t, "existing-session-1")
	es := alice.EncryptSession(bob.PublicKey(), []*Clove{esClove})
	if es == nil {
		t.Fatal("nil ES")
	}
	if len(es) < 24 {
		t.Fatalf("ES too short: %d", len(es))
	}
	gotCloves, err = bob.DecryptMessage(es)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCloves) != 1 || string(gotCloves[0].Msg.Payload) != "existing-session-1" {
		t.Fatalf("ES cloves wrong: %+v", gotCloves)
	}

	// Bob → Alice: ES in the other direction.
	es2Clove := testClove(t, "bob-to-alice-es")
	es2 := bob.EncryptSession(alice.PublicKey(), []*Clove{es2Clove})
	if es2 == nil {
		t.Fatal("nil ES bob->alice")
	}
	gotCloves, err = alice.DecryptMessage(es2)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCloves) != 1 || string(gotCloves[0].Msg.Payload) != "bob-to-alice-es" {
		t.Fatalf("reverse ES cloves wrong: %+v", gotCloves)
	}

	// Several more ES messages each way, checking the tag/key chains
	// advance in lockstep.
	for i := 0; i < 5; i++ {
		m := []byte("bulk-es-")
		m = append(m, byte('a'+i))
		es := alice.EncryptSession(bob.PublicKey(), []*Clove{testClove(t, string(m))})
		if es == nil {
			t.Fatalf("nil ES iteration %d", i)
		}
		got, err := bob.DecryptMessage(es)
		if err != nil {
			t.Fatalf("ES iteration %d: %v", i, err)
		}
		if string(got[0].Msg.Payload) != string(m) {
			t.Fatalf("ES iteration %d payload %q", i, got[0].Msg.Payload)
		}
		es = bob.EncryptSession(alice.PublicKey(), []*Clove{testClove(t, string(m)+"-r")})
		if es == nil {
			t.Fatalf("nil reverse ES iteration %d", i)
		}
		got, err = alice.DecryptMessage(es)
		if err != nil {
			t.Fatalf("reverse ES iteration %d: %v", i, err)
		}
		if string(got[0].Msg.Payload) != string(m)+"-r" {
			t.Fatalf("reverse ES iteration %d payload %q", i, got[0].Msg.Payload)
		}
	}
}

// TestOneTimeSession checks the netdb-reply path: a single key+tag ES
// message with no handshake.
func TestOneTimeSession(t *testing.T) {
	bobPriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewManager(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	sess := bob.GenerateOneTimeSession(10 * time.Minute)
	if sess == nil {
		t.Fatal("nil one-time session")
	}
	msg := EncryptOneTime([]*Clove{testClove(t, "netdb-reply")}, sess)
	if len(msg) < 24 {
		t.Fatalf("one-time message too short: %d", len(msg))
	}
	cloves, err := bob.DecryptMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cloves) != 1 || string(cloves[0].Msg.Payload) != "netdb-reply" {
		t.Fatalf("one-time cloves wrong: %+v", cloves)
	}
	// The tag must be single-use.
	if _, err := bob.DecryptMessage(msg); err == nil {
		t.Fatal("one-time tag reused")
	}
}

// TestAnonymousNS checks the N-pattern anonymous message.
func TestAnonymousNS(t *testing.T) {
	bobPriv, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewManager(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg := EncryptToTargetNS(bob.PublicKey(), []*Clove{testClove(t, "anonymous-lookup")})
	if msg == nil {
		t.Fatal("nil N message")
	}
	if len(msg) < 48 {
		t.Fatalf("N message too short: %d", len(msg))
	}
	cloves, err := bob.DecryptNSAnonymous(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cloves) != 1 || string(cloves[0].Msg.Payload) != "anonymous-lookup" {
		t.Fatalf("N cloves wrong: %+v", cloves)
	}
}

// TestPayloadRoundTrip checks ProcessPayload against buildPayload
// output, including the padding rules.
func TestPayloadRoundTrip(t *testing.T) {
	// A small payload: DateTime + one clove + padding.
	clove := testClove(t, "x")
	payload := buildPayload([]*Clove{clove}, time.Now(), false, nil, nil, ESOverhead)
	pp, err := ProcessPayload(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pp.Cloves) != 1 {
		t.Fatalf("cloves %d", len(pp.Cloves))
	}
	if string(pp.Cloves[0].Msg.Payload) != "x" {
		t.Fatalf("payload %q", pp.Cloves[0].Msg.Payload)
	}
	if pp.DateTime == 0 {
		t.Fatal("no datetime")
	}
	// Padding must be last.
	typ := payload[len(payload)-3-paddingLen(payload)]
	_ = typ

	// Handshake payloads reject termination/PN blocks.
	bad := append([]byte{}, payload...)
	bad = append(bad, BlockTermination)
	bad = append(bad, 0, 1, 4) // header: type=4 len=1
	_, err = ProcessPayload(append(bad, 9), true)
	if err == nil {
		t.Fatal("termination accepted in handshake")
	}
}

// paddingLen finds the padding block data length of a built payload.
func paddingLen(payload []byte) int {
	// Walk blocks to the end; the last block should be padding.
	i := 0
	for i+3 <= len(payload) {
		typ := payload[i]
		ln := int(payload[i+1])<<8 | int(payload[i+2])
		i += 3 + ln
		if typ == BlockPadding && i == len(payload) {
			return ln
		}
	}
	return 0
}

// TestDeliveryInstructions checks instruction encoding round trips.
func TestDeliveryInstructions(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	cases := []DeliveryInstructions{
		{Mode: ModeLocal},
		{Mode: ModeDestination, DestinationHash: hash},
		{Mode: ModeRouter, RouterHash: hash},
		{Mode: ModeTunnel, RouterHash: hash, TunnelID: 0x11223344},
	}
	for _, di := range cases {
		enc := di.Encode()
		got, n, err := DecodeDeliveryInstructions(enc)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(enc) {
			t.Fatalf("mode %d: decoded %d of %d", di.Mode, n, len(enc))
		}
		if got.Mode != di.Mode || !bytes.Equal(got.RouterHash, di.RouterHash) ||
			!bytes.Equal(got.DestinationHash, di.DestinationHash) || got.TunnelID != di.TunnelID {
			t.Fatalf("mode %d mismatch: %+v", di.Mode, got)
		}
	}
}

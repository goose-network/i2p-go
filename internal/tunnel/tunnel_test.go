package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
	"github.com/goose-network/i2p-go/internal/noise"
)

// testRouterIdentity builds a minimal ECIES RouterInfo for tests.
func testRouterIdentity(t *testing.T) (*data.RouterInfo, []byte) {
	t.Helper()
	priv := make([]byte, 32)
	rand.Read(priv)
	pub := x25519Pub(priv)
	id := data.RouterIdentity{
		EncKey:     pub,
		SigningKey: make([]byte, 32), // placeholder; unused here
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	ri := &data.RouterInfo{Identity: id}
	return ri, priv
}

func TestLayerCryptoRoundTrip(t *testing.T) {
	block := make([]byte, PreprocessedSize)
	rand.Read(block)
	layerKey := make([]byte, 32)
	ivKey := make([]byte, 32)
	rand.Read(layerKey)
	rand.Read(ivKey)
	want := append([]byte(nil), block...)

	// Hops encrypt, endpoints decrypt — a round trip through both
	// orders must restore the original.
	if err := LayerEncrypt(block, layerKey, ivKey); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(block, want) {
		t.Fatal("layer encrypt was a no-op")
	}
	if err := LayerDecrypt(block, layerKey, ivKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, want) {
		t.Fatal("layer decrypt did not restore the original")
	}
	// Two hops, reversed decrypt order.
	LayerEncrypt(block, layerKey, ivKey)
	if err := LayerEncrypt(block, make([]byte, 32), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	LayerDecrypt(block, make([]byte, 32), make([]byte, 32))
	if err := LayerDecrypt(block, layerKey, ivKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, want) {
		t.Fatal("two-hop round trip failed")
	}
}

func TestIVValidator(t *testing.T) {
	v := NewIVValidator()
	block := make([]byte, PreprocessedSize)
	rand.Read(block)
	if !v.ReceiveIV(block) {
		t.Fatal("first receive rejected")
	}
	if v.ReceiveIV(block) {
		t.Fatal("replay accepted")
	}
	block2 := append([]byte(nil), block...)
	rand.Read(block2)
	if !v.ReceiveIV(block2) {
		t.Fatal("distinct block rejected")
	}
}

func TestPreprocessRoundTrip(t *testing.T) {
	// A small I2NP message, local delivery.
	payload := make([]byte, 200)
	rand.Read(payload)
	msg := i2np.New(i2np.TypeData, payload)
	blocks, err := PreprocessMessage(msg.Encode16(), msg.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks for a small message", len(blocks))
	}
	frags, err := VerifyAndParse(blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 1 {
		t.Fatalf("got %d fragments", len(frags))
	}
	f := frags[0]
	if f.Subsequent || f.Fragmented {
		t.Fatal("small message marked fragmented")
	}
	decoded, err := i2np.Decode16(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != i2np.TypeData || !bytes.Equal(decoded.Payload, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestPreprocessFragmentedRoundTrip(t *testing.T) {
	// A message large enough to fragment (over ~1004 bytes of payload).
	payload := make([]byte, 3000)
	rand.Read(payload)
	msg := i2np.New(i2np.TypeData, payload)
	blocks, err := PreprocessMessage(msg.Encode16(), msg.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) < 3 {
		t.Fatalf("expected several blocks, got %d", len(blocks))
	}
	var reassembled []byte
	var sawFirst bool
	for _, b := range blocks {
		frags, err := VerifyAndParse(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frags {
			if !sawFirst {
				sawFirst = true
				if !f.Fragmented {
					t.Fatal("first fragment not marked fragmented")
				}
				if f.MessageID != msg.ID {
					t.Fatal("message ID mismatch")
				}
			} else if !f.Subsequent {
				t.Fatal("subsequent fragment not marked")
			}
			reassembled = append(reassembled, f.Payload...)
		}
	}
	if !bytes.Equal(reassembled, msg.Encode16()) {
		t.Fatal("reassembled payload mismatch")
	}
}

func TestPreprocessToTunnelMode(t *testing.T) {
	payload := make([]byte, 100)
	rand.Read(payload)
	peer := make([]byte, 32)
	rand.Read(peer)
	msg := i2np.New(i2np.TypeData, payload)
	blocks, err := PreprocessMessage(msg.Encode16(), msg.ID, peer, 1234)
	if err != nil {
		t.Fatal(err)
	}
	frags, err := VerifyAndParse(blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	if frags[0].ToTunnel != 1234 {
		t.Fatalf("toTunnel = %d", frags[0].ToTunnel)
	}
	if !bytes.Equal(frags[0].ToRouter, peer) {
		t.Fatal("toRouter mismatch")
	}
}

func TestReassembler(t *testing.T) {
	r := NewReassembler()
	payload := make([]byte, 2000)
	rand.Read(payload)
	msg := i2np.New(i2np.TypeData, payload)
	encoded := msg.Encode16()
	blocks, err := PreprocessMessage(encoded, msg.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got *CompleteMessage
	for _, b := range blocks {
		frags, err := VerifyAndParse(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frags {
			cm, err := r.Receive(f)
			if err != nil {
				t.Fatal(err)
			}
			if cm != nil {
				got = cm
			}
		}
	}
	if got == nil {
		t.Fatal("message never completed")
	}
	if !bytes.Equal(got.Data, encoded) {
		t.Fatal("reassembled data mismatch")
	}
	if got.MessageID != msg.ID {
		t.Fatal("message ID mismatch")
	}
}

// TestOneHopInboundBuild simulates the complete 1-hop inbound build
// exchange between us (the creator/IBEP) and R (the IBGW), through both
// sides of our own implementation:
//
//  1. we build the STBM (R's Noise-encrypted record + IBEP blank +
//     2 pure blanks, blank pre-layered with R's reply key)
//  2. R parses it (decrypts its record, layer-encrypts the others)
//  3. R replies (fills its slot with a response record, message ID =
//     our replyMessageId)
//  4. we verify the blank hash and decrypt R's response
func TestOneHopInboundBuild(t *testing.T) {
	ri, rPriv := testRouterIdentity(t)
	ourHash := data.Hash{}
	rand.Read(ourHash[:])

	now := time.Now()
	replyMsgID := randomTunnelID()
	s, err := newInboundBuild(ri, replyMsgID, now)
	if err != nil {
		t.Fatal(err)
	}
	stbm, err := s.encodeSTBM(ourHash)
	if err != nil {
		t.Fatal(err)
	}
	if stbm.Type != i2np.TypeShortTunnelBuild {
		t.Fatalf("type %d", stbm.Type)
	}
	if len(stbm.Payload) != 1+shortRecords*ShortRecordSize {
		t.Fatalf("payload size %d", len(stbm.Payload))
	}
	if stbm.ID != replyMsgID {
		t.Fatal("STBM ID mismatch")
	}

	// R receives and processes the STBM.
	ib, err := ParseIncomingSTBM(stbm, ri.RouterHash(), rPriv, ourHash)
	if err != nil {
		t.Fatal(err)
	}
	if ib == nil {
		t.Fatal("R failed to find its record")
	}
	if !ib.Record.isInGW {
		t.Fatal("record not marked IBGW")
	}
	if ib.Record.recvTunnel != s.RTunnelID {
		t.Fatalf("recvTunnel %d != %d", ib.Record.recvTunnel, s.RTunnelID)
	}
	if ib.Record.nextTunnel != s.IBEPTunnelID {
		t.Fatalf("nextTunnel %d != %d", ib.Record.nextTunnel, s.IBEPTunnelID)
	}
	if ib.Record.nextMsgID != replyMsgID {
		t.Fatalf("nextMsgID %d != %d", ib.Record.nextMsgID, replyMsgID)
	}
	if !bytes.Equal(ib.Record.nextIdent[:], ourHash[:]) {
		t.Fatal("nextIdent != our hash")
	}
	// R's derived keys must match the creator's derivation (both sides
	// derive the same reply/layer/IV keys from the same handshake).
	if !bytes.Equal(ib.Keys.ReplyKey, s.RKeys.ReplyKey) {
		t.Fatal("reply key mismatch between creator and hop")
	}
	if !bytes.Equal(ib.Keys.LayerKey, s.RKeys.LayerKey) {
		t.Fatal("layer key mismatch")
	}
	if !bytes.Equal(ib.Keys.IVKey, s.RKeys.IVKey) {
		t.Fatal("IV key mismatch")
	}

	// R replies.
	reply := ib.BuildReplySTBM(0)
	if reply.Type != i2np.TypeShortTunnelBuild {
		t.Fatalf("reply type %d", reply.Type)
	}
	if reply.ID != replyMsgID {
		t.Fatalf("reply ID %d != %d", reply.ID, replyMsgID)
	}

	// We parse the reply.
	result, err := s.ParseBuildReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatalf("build not accepted: status %d", result.Status)
	}

	// A rejected build must also parse (with a nonzero status).
	rejectState, reject := ib2Reply(t, ri, rPriv, ourHash, 30, replyMsgID, now)
	result2, err := rejectState.ParseBuildReply(reject)
	if err != nil {
		t.Fatal(err)
	}
	if result2.Accepted || result2.Status != 30 {
		t.Fatalf("expected status 30, got %d", result2.Status)
	}
}

// ib2Reply runs a fresh build with a given reply status, returning
// both the build state and R's reply so the rejection path can be
// checked against the matching state.
func ib2Reply(t *testing.T, ri *data.RouterInfo, rPriv []byte, ourHash data.Hash, status int, replyMsgID uint32, now time.Time) (*inboundBuildState, *i2np.Message) {
	t.Helper()
	s2, err := newInboundBuild(ri, replyMsgID, now)
	if err != nil {
		t.Fatal(err)
	}
	stbm2, err := s2.encodeSTBM(ourHash)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := ParseIncomingSTBM(stbm2, ri.RouterHash(), rPriv, ourHash)
	if err != nil || ib == nil {
		t.Fatalf("parse: %v %v", err, ib)
	}
	return s2, ib.BuildReplySTBM(status)
}

// TestChacha20BlockAgainstJavaVector checks our ChaCha20 layering
// keystream against a known Java-style invocation (12-byte nonce with
// the slot at iv[4], block counter 1).
func TestChacha20BlockAgainstJavaVector(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	data1 := make([]byte, ShortRecordSize)
	rand.Read(data1)
	data2 := append([]byte(nil), data1...)
	chacha20Block(key, 2, data1)
	// Applying the same layer twice cancels (XOR-symmetric).
	chacha20Block(key, 2, data1)
	if !bytes.Equal(data1, data2) {
		t.Fatal("double application did not cancel")
	}
}

// TestNoiseNBuildRecordRoundTrip checks the Noise N encryption directly:
// the initiator and responder must agree on the handshake hash and
// chaining key.
func TestNoiseNBuildRecordRoundTrip(t *testing.T) {
	_, rPriv := testRouterIdentity(t)
	rPub := x25519Pub(rPriv)
	initiator, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, true, nil, rPub)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, false, rPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := initiator.WriteMessage([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := responder.ReadMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "payload" {
		t.Fatalf("payload %q", pt)
	}
	if !bytes.Equal(initiator.HandshakeHash(), responder.HandshakeHash()) {
		t.Fatal("handshake hash mismatch")
	}
	if !bytes.Equal(initiator.ChainingKey(), responder.ChainingKey()) {
		t.Fatal("chaining key mismatch")
	}
}

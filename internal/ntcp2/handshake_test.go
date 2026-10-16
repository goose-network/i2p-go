package ntcp2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2pcrypto"
	"github.com/goose-network/i2p-go/internal/noise"
)

// mockBob plays the Bob side of the NTCP2 handshake against our Alice
// implementation, following InboundEstablishState. It reads msg1,
// replies msg2, reads msg3, verifies the RI block, and derives the
// data-phase keys.
type mockBob struct {
	hs *noise.HandshakeState
	// The AES-256 key is Bob's own router hash (Bob's view of aesobfse).
	aesKey []byte
	aesIV  [16]byte
}

func newMockBob(t *testing.T, bobStaticPriv []byte, bobHash []byte, bobIV [16]byte) *mockBob {
	t.Helper()
	hs, err := noise.NewHandshakeState(ProtocolName, noise.XK, false, bobStaticPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &mockBob{hs: hs, aesKey: append([]byte(nil), bobHash...), aesIV: bobIV}
}

func (b *mockBob) receiveMsg1(t *testing.T, msg []byte) {
	t.Helper()
	if len(msg) < msg1Size {
		t.Fatalf("msg1 short %d", len(msg))
	}
	// Save the msg2 IV before deobfuscating X.
	var iv2 [16]byte
	copy(iv2[:], msg[keySize-ivSize:keySize])
	if err := Deobfuscate(msg[:keySize], b.aesKey, b.aesIV[:]); err != nil {
		t.Fatal(err)
	}
	b.aesIV = iv2
	opts, err := b.hs.ReadMessage(msg[:msg1Size])
	if err != nil {
		t.Fatal("msg1:", err)
	}
	if len(opts) != options1Size {
		t.Fatalf("options1 length %d", len(opts))
	}
	if opts[0] != NetworkID {
		t.Fatalf("network id %d", opts[0])
	}
	if opts[1] != NTCP2Version {
		t.Fatalf("version %d", opts[1])
	}
	padlen1 := int(binary.BigEndian.Uint16(opts[2:4]))
	msg3p2len := int(binary.BigEndian.Uint16(opts[4:6]))
	tsA := binary.BigEndian.Uint32(opts[8:12])
	if d := time.Since(time.UnixMilli(int64(tsA) * 1000)); d > time.Minute {
		t.Fatalf("msg1 timestamp off by %v", d)
	}
	if padlen1 != len(msg)-msg1Size {
		t.Fatalf("padlen1 %d but %d trailing bytes", padlen1, len(msg)-msg1Size)
	}
	if padlen1 > 0 {
		b.hs.MixHash(msg[msg1Size:])
	}
	_ = msg3p2len
}

func (b *mockBob) sendMsg2(w io.Writer) error {
	var opts [options2Size]byte
	// padlen2 at offset 2:4, timestamp at 8:12; the rest zero.
	binary.BigEndian.PutUint32(opts[8:12], uint32(time.Now().Unix()))
	msg, err := b.hs.WriteMessage(opts[:])
	if err != nil {
		return err
	}
	if len(msg) != msg2Size {
		return io.ErrShortBuffer
	}
	if err := Obfuscate(msg[:keySize], b.aesKey, b.aesIV[:]); err != nil {
		return err
	}
	_, err = w.Write(msg)
	return err
}

func (b *mockBob) receiveMsg3(t *testing.T, msg []byte) {
	t.Helper()
	if len(msg) < msg3P1Size+macSize {
		t.Fatalf("msg3 short %d", len(msg))
	}
	payload, err := b.hs.ReadMessage(msg)
	if err != nil {
		t.Fatal("msg3:", err)
	}
	parsed, err := ParseBlocks(payload, true)
	if err != nil {
		t.Fatal("msg3 blocks:", err)
	}
	if len(parsed.Blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(parsed.Blocks))
	}
	if parsed.Blocks[0].Type != BlockRouterInfo {
		t.Fatalf("first block type %d", parsed.Blocks[0].Type)
	}
	if parsed.Blocks[1].Type != BlockOptions {
		t.Fatalf("second block type %d", parsed.Blocks[1].Type)
	}
	if parsed.Blocks[2].Type != BlockPadding {
		t.Fatalf("third block type %d", parsed.Blocks[2].Type)
	}
}

func (b *mockBob) dataPhase() (send, recv *i2pcrypto.AEAD, sipAB, sipBA []byte) {
	// Bob: send = k2 (b2a), recv = k1 (a2b).
	send, recv, _ = b.hs.Split()
	sipAB, sipBA = GenerateSipHashKeys(b.hs.ChainingKey(), b.hs.HandshakeHash())
	return
}

// testRouterInfo builds a minimal signed RouterInfo for Alice.
func testRouterInfo(t *testing.T) (ri data.RouterInfo, raw []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	encKey := bytes.Repeat([]byte{7}, 32)
	id := data.RouterIdentity{
		EncKey:     encKey,
		SigningKey: priv.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	ri = data.RouterInfo{
		Identity:  id,
		Published: time.Now(),
		Options: map[string]string{
			"caps":           "R",
			"netId":          "2",
			"router.version": "0.9.70",
		},
	}
	if err := ri.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ri, ri.Bytes()
}

// TestHandshakeRoundTrip runs a complete outbound NTCP2 handshake over
// an in-memory pipe, with a mock Bob implementing the inbound side
// from the Java reference, then exchanges data-phase frames both ways.
func TestHandshakeRoundTrip(t *testing.T) {
	aliceRI, aliceRaw := testRouterInfo(t)
	// Bob's static key and router hash.
	var bobStaticPriv [32]byte
	for i := range bobStaticPriv {
		bobStaticPriv[i] = byte(i + 3)
	}
	bobHash := sha256.Sum256([]byte("bob's router identity"))
	var bobIV [16]byte
	for i := range bobIV {
		bobIV[i] = byte(i * 3)
	}

	// Derive Bob's static public key for Alice's config.
	aliceCfg := &OutboundConfig{
		BobStatic:     mustPublic(t, bobStaticPriv[:]),
		BobIV:         bobIV,
		BobRouterHash: bobHash[:],
		AliceRI:       aliceRaw,
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Bob in a goroutine.
	bobDone := make(chan error, 1)
	go func() {
		bob := newMockBob(t, bobStaticPriv[:], bobHash[:], bobIV)
		buf := make([]byte, 4096)
		n, err := server.Read(buf)
		if err != nil {
			bobDone <- err
			return
		}
		bob.receiveMsg1(t, buf[:n])
		if err := bob.sendMsg2(server); err != nil {
			bobDone <- err
			return
		}
		n, err = server.Read(buf)
		if err != nil {
			bobDone <- err
			return
		}
		bob.receiveMsg3(t, buf[:n])

		// Data phase from Bob's side: read one frame from Alice, send
		// one frame back.
		send, recv, sipAB, sipBA := bob.dataPhase()
		bobConn := &Conn{
			conn:    server,
			reader:  server,
			send:    send,
			recv:    recv,
			sendSip: newSipState(sipBA), // Bob sends b2a
			recvSip: newSipState(sipAB), // and receives a2b
		}
		// Bob's Split() returns swapped keys (responder), so map them:
		// send=b2a uses sip_ba, recv=a2b uses sip_ab.
		got, err := bobConn.readFrame()
		if err != nil {
			bobDone <- err
			return
		}
		parsed, err := ParseBlocks(got, false)
		if err != nil {
			bobDone <- err
			return
		}
		if len(parsed.Blocks) != 1 || parsed.Blocks[0].Type != BlockI2NP {
			bobConn.Close(TerminatePayload)
			bobDone <- io.ErrUnexpectedEOF
			return
		}
		if err := bobConn.writeBlocks([]Block{DateTimeBlock(time.Now())}); err != nil {
			bobConn.Close(TerminatePayload)
			bobDone <- err
			return
		}
		// Send a termination to end Alice's read loop.
		if err := bobConn.writeBlocks([]Block{TerminationBlock(TerminateTermination, 42)}); err != nil {
			bobConn.Close(TerminateTermination)
			bobDone <- err
			return
		}
		bobDone <- nil
	}()

	// Alice: run the handshake.
	conn, err := HandshakeOutbound(client, aliceCfg)
	if err != nil {
		t.Fatal("handshake:", err)
	}
	_ = aliceRI

	// Data phase: Alice sends an I2NP-ish block.
	fakeMsg := append([]byte{3}, bytes.Repeat([]byte{9}, 40)...)
	if err := conn.SendI2NP(fakeMsg); err != nil {
		t.Fatal("send:", err)
	}
	// Read frames until termination.
	termSeen := false
	for i := 0; i < 4 && !termSeen; i++ {
		if err := conn.ReadFrame(); err != nil {
			if err == ErrTerminated {
				termSeen = true
				break
			}
			t.Fatal("read:", err)
		}
		if conn.Terminated {
			termSeen = true
		}
	}
	if !termSeen {
		t.Fatal("no termination received")
	}
	if conn.TermReason != TerminateTermination {
		t.Fatalf("term reason %d", conn.TermReason)
	}
	if err := <-bobDone; err != nil {
		t.Fatal("bob:", err)
	}
}

// TestParseBlocks checks payload block validation rules.
func TestParseBlocks(t *testing.T) {
	// Padding must be last.
	bad := EncodeBlocks([]Block{
		{Type: BlockPadding, Data: make([]byte, 4)},
		{Type: BlockDateTime, Data: make([]byte, 4)},
	})
	if _, err := ParseBlocks(bad, false); err == nil {
		t.Fatal("padding not last accepted")
	}
	// Handshake first block must be the RI.
	bad2 := EncodeBlocks([]Block{
		{Type: BlockOptions, Data: make([]byte, 12)},
		{Type: BlockPadding},
	})
	if _, err := ParseBlocks(bad2, true); err == nil {
		t.Fatal("non-RI first handshake block accepted")
	}
	// Datetime length must be 4.
	bad3 := EncodeBlocks([]Block{
		{Type: BlockDateTime, Data: make([]byte, 3)},
	})
	if _, err := ParseBlocks(bad3, false); err == nil {
		t.Fatal("short datetime accepted")
	}
	// Good empty payload is fine in data phase.
	if _, err := ParseBlocks(nil, false); err != nil {
		t.Fatal(err)
	}
	// Empty payload is not fine in handshake.
	if _, err := ParseBlocks(nil, true); err == nil {
		t.Fatal("empty handshake payload accepted")
	}
	// Round-trip datetime (second resolution).
	good := EncodeBlocks([]Block{DateTimeBlock(time.UnixMilli(1234567890123))})
	parsed, err := ParseBlocks(good, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.DateTime.UnixMilli() / 1000; got != 1234567890123/1000 {
		t.Fatalf("datetime %v", parsed.DateTime)
	}
}

func mustPublic(t *testing.T, priv []byte) [32]byte {
	t.Helper()
	hs, err := noise.NewHandshakeState(ProtocolName, noise.XK, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Use the noise package's test hook via a fresh state whose static
	// matches priv: construct directly.
	pub, err := publicOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = hs
	return pub
}

// publicOf derives the static public key through the noise package.
func publicOf(priv []byte) ([32]byte, error) {
	var pub [32]byte
	p, err := noise.Public(priv)
	if err != nil {
		return pub, err
	}
	copy(pub[:], p)
	return pub, nil
}

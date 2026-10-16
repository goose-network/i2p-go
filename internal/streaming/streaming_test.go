// Streaming protocol tests: wire format round-trips, signatures, the
// I2CP payload layer, and end-to-end streams over an in-memory
// transport with loss and reordering injection.
package streaming

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// testDest builds a deterministic Ed25519 destination.
func testDest(t *testing.T, seed byte) (*data.Destination, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	enc := make([]byte, 32)
	for i := range enc {
		enc[i] = seed*7 + byte(i)
	}
	dest := &data.Destination{
		EncKey:     enc,
		SigningKey: priv.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	return dest, priv
}

// ---- packet.go ----

func TestPacketRoundTrip(t *testing.T) {
	dest, priv := testDest(t, 1)
	p := &Packet{
		SendStreamID:    0x01020304,
		ReceiveStreamID: 0x05060708,
		SequenceNum:     42,
		AckThrough:      41,
		Nacks:           []uint32{40, 39},
		ResendDelay:     5,
		Flags:           FlagDelayRequested | FlagFromIncluded | FlagMaxPacketSize | FlagSignatureIncluded | FlagClose,
		OptionalDelay:   300,
		OptionalFrom:    dest,
		OptionalMaxSize: 1730,
		Payload:         []byte("hello streaming"),
	}
	p.Sign(priv)
	raw := p.Encode()

	// Wire offsets: ids, ids, seq, ack, nackCount...
	if got := binary.BigEndian.Uint32(raw[0:]); got != p.SendStreamID {
		t.Fatalf("sendStreamId at offset 0: %08x", got)
	}
	if got := binary.BigEndian.Uint32(raw[4:]); got != p.ReceiveStreamID {
		t.Fatalf("receiveStreamId at offset 4: %08x", got)
	}
	if got := binary.BigEndian.Uint32(raw[8:]); got != 42 {
		t.Fatalf("sequenceNum at offset 8: %d", got)
	}
	if got := binary.BigEndian.Uint32(raw[12:]); got != 41 {
		t.Fatalf("ackThrough at offset 12: %d", got)
	}
	if raw[16] != 2 {
		t.Fatalf("nackCount at offset 16: %d", raw[16])
	}
	if got := binary.BigEndian.Uint32(raw[17:]); got != 40 {
		t.Fatalf("first nack at offset 17: %d", got)
	}
	// nackCount(1) + 2*4 nacks + resendDelay(1) + flags(2) + optionSize(2)
	if got := binary.BigEndian.Uint16(raw[26:]); got != p.Flags {
		t.Fatalf("flags at offset 26: %04x", got)
	}

	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SendStreamID != p.SendStreamID || got.ReceiveStreamID != p.ReceiveStreamID {
		t.Fatal("stream ids mismatch")
	}
	if got.SequenceNum != 42 || got.AckThrough != 41 {
		t.Fatalf("seq/ack mismatch: %d/%d", got.SequenceNum, got.AckThrough)
	}
	if got.ResendDelay != 5 || got.Flags != p.Flags || got.OptionalDelay != 300 {
		t.Fatal("header fields mismatch")
	}
	if len(got.Nacks) != 2 || got.Nacks[0] != 40 || got.Nacks[1] != 39 {
		t.Fatal("nacks mismatch")
	}
	if got.OptionalMaxSize != 1730 {
		t.Fatalf("maxSize mismatch: %d", got.OptionalMaxSize)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Fatal("payload mismatch")
	}
	if got.OptionalFrom == nil || !data.DestinationHash(*got.OptionalFrom).Equal(data.DestinationHash(*dest)) {
		t.Fatal("FROM mismatch")
	}
	if !got.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("signature does not verify after round trip")
	}
}

// Unset sequence/ack numbers (Java's -1 convention) serialize as 0.
func TestPacketNegativeClamps(t *testing.T) {
	p := &Packet{SequenceNum: -1, AckThrough: -1, Flags: FlagNoAck}
	raw := p.Encode()
	if binary.BigEndian.Uint32(raw[8:]) != 0 || binary.BigEndian.Uint32(raw[12:]) != 0 {
		t.Fatal("negative values must serialize as zero")
	}
	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SequenceNum != 0 || got.AckThrough != 0 {
		t.Fatal("parsed zeros")
	}
}

func TestPacketParseErrors(t *testing.T) {
	if _, err := ParsePacket([]byte("short")); err == nil {
		t.Fatal("no error for short packet")
	}
	// Option size larger than the buffer: optionSize sits at the end of
	// the fixed header (headerLen - 2, no nacks present).
	p := &Packet{Flags: FlagDelayRequested, OptionalDelay: 1}
	raw := p.Encode()
	raw[packetHeaderLen-2] = 0xff // optionSize high byte
	if _, err := ParsePacket(raw); err == nil {
		t.Fatal("no error for option overflow")
	}
}

func TestPacketSignature(t *testing.T) {
	dest, priv := testDest(t, 3)
	_, wrongPriv := testDest(t, 4)

	p := &Packet{SequenceNum: 7, Payload: []byte("data")}
	p.Sign(priv)
	if !p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("signature should verify with signer key")
	}
	if p.Verify(wrongPriv.Public().(ed25519.PublicKey)) {
		t.Fatal("signature must fail with wrong key")
	}

	// FROM included: verification uses the FROM's key.
	p2 := &Packet{SequenceNum: 8, OptionalFrom: dest, Payload: []byte("from data")}
	p2.Sign(priv)
	if !p2.Verify(wrongPriv.Public().(ed25519.PublicKey)) {
		t.Fatal("FROM key must take precedence over the supplied key")
	}
	if p2.Verify(nil) != true {
		t.Fatal("Verify(nil) should use the FROM key")
	}

	// Tampering with any field breaks it.
	p3 := &Packet{SequenceNum: 9, Payload: []byte("original")}
	p3.Sign(priv)
	raw := p3.Encode()
	raw[len(raw)-1] ^= 0xff
	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("tampered payload must not verify")
	}

	// A signature from a different destination's key, presented with the
	// wrong FROM, must fail.
	p4 := &Packet{SequenceNum: 10, OptionalFrom: dest, Payload: []byte("forged")}
	p4.Sign(wrongPriv)
	if p4.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("forged FROM must not verify")
	}
}

// TestPacketOfflineSignature round-trips an offline-signed packet the
// way zzz.i2p's streaming layer sends them: the destination's real key
// authorizes a transient key (signature over expires+type+SPK) and the
// transient key signs the packet itself.
func TestPacketOfflineSignature(t *testing.T) {
	dest, realPriv := testDest(t, 5)
	transPub, transPriv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := uint32(time.Now().Add(time.Hour).Unix())

	// The offline signature by the real key over the transient block.
	var block []byte
	block = binary.BigEndian.AppendUint32(block, expires)
	block = binary.BigEndian.AppendUint16(block, uint16(data.SigEdDSA_SHA512_Ed25519))
	block = append(block, transPub...)
	offlineSig := ed25519.Sign(realPriv, block)

	p := &Packet{
		SequenceNum:      1,
		Flags:            FlagSYN | FlagFromIncluded | FlagSignatureIncluded | FlagMaxPacketSize | FlagSignatureOffline,
		OptionalFrom:     dest,
		OptionalMaxSize:  1730,
		TransientExpires: expires,
		TransientSigType: data.SigEdDSA_SHA512_Ed25519,
		TransientSPK:     transPub,
		OfflineSignature: offlineSig,
		Payload:          []byte("syn-ack"),
	}
	p.OptionalSig = ed25519.Sign(transPriv, p.encode(ed25519.SignatureSize))

	// Wire round trip: the parse must recover the transient block and
	// the signature separately (they share the option area).
	got, err := ParsePacket(p.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verify(dest.SigningKey) {
		t.Fatal("offline signature should verify with the FROM's real key")
	}
	// The caller's key is ignored when FROM is present.
	if !got.Verify(nil) {
		t.Fatal("Verify must use the FROM key")
	}
	if !bytes.Equal(got.TransientSPK, transPub) {
		t.Fatal("transient SPK mismatch after round trip")
	}

	// Wrong transient key in the block: the offline signature fails.
	got.TransientSPK[0] ^= 1
	if got.Verify(dest.SigningKey) {
		t.Fatal("tampered transient SPK must not verify")
	}

	// Expired transient key.
	got2, err := ParsePacket(p.Encode())
	if err != nil {
		t.Fatal(err)
	}
	got2.TransientExpires = uint32(time.Now().Add(-time.Hour).Unix())
	// Re-sign the offline block so only the expiry is wrong.
	var b2 []byte
	b2 = binary.BigEndian.AppendUint32(b2, got2.TransientExpires)
	b2 = binary.BigEndian.AppendUint16(b2, uint16(data.SigEdDSA_SHA512_Ed25519))
	b2 = append(b2, transPub...)
	got2.OfflineSignature = ed25519.Sign(realPriv, b2)
	if got2.Verify(dest.SigningKey) {
		t.Fatal("expired transient key must not verify")
	}
}

// ---- payload.go ----

func TestPayloadRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 66, 67, 512, 8192}
	for _, size := range sizes {
		plain := make([]byte, size)
		rand.Read(plain)
		gz, err := CompressPayload(plain, ProtoStreaming, 1234, 80)
		if err != nil {
			t.Fatal(err)
		}
		if len(gz) < 10 {
			t.Fatal("too short")
		}
		got, proto, fromPort, toPort, err := DecompressPayload(gz)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: payload mismatch", size)
		}
		if proto != ProtoStreaming || fromPort != 1234 || toPort != 80 {
			t.Fatalf("size %d: header fields %d/%d/%d", size, proto, fromPort, toPort)
		}
	}
}

// Small payloads must use Java's byte-identical stored-format member.
func TestZeroCompressFormat(t *testing.T) {
	plain := []byte("streaming over i2p")
	gz, err := CompressPayload(plain, ProtoUnspecified, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff,
		0x01, byte(len(plain)), byte(len(plain) >> 8),
		^byte(len(plain)), ^byte(len(plain) >> 8),
	}
	want = append(want, plain...)
	want = binary.LittleEndian.AppendUint32(want, crc32.ChecksumIEEE(plain))
	want = binary.LittleEndian.AppendUint32(want, uint32(len(plain)))
	if !bytes.Equal(gz, want) {
		t.Fatalf("stored-format mismatch:\n got %x\nwant %x", gz, want)
	}

	// The OS byte (proto) gets stamped even in stored mode.
	if gz[protoByte] != ProtoUnspecified {
		t.Fatalf("proto byte %d", gz[protoByte])
	}
	// And decodes back with proto normalized to 0.
	_, proto, _, _, err := DecompressPayload(gz)
	if err != nil {
		t.Fatal(err)
	}
	if proto != 0 {
		t.Fatalf("unspecified proto decoded as %d", proto)
	}
}

// ---- end-to-end over an in-memory transport ----

// loopTransport routes packets between in-memory managers, simulating
// the I2P network: the raw streaming packet is wrapped in the I2CP
// payload format (proto + ports stamped into the gzip header) and
// delivered to the peer's HandleMessage. A hook can drop or delay
// packets.
type loopTransport struct {
	mu    sync.Mutex
	peers map[data.Hash]*Manager
	hook  func(p *Packet) (drop bool, delay time.Duration)
	sent  []*Packet // every packet handed to the transport, in order
}

func newLoopTransport() *loopTransport {
	return &loopTransport{peers: make(map[data.Hash]*Manager)}
}

func (tr *loopTransport) add(m *Manager) {
	tr.mu.Lock()
	tr.peers[m.ourHash] = m
	tr.mu.Unlock()
}

func (tr *loopTransport) SendPacket(to *data.Destination, packet []byte, fromPort, toPort uint16) error {
	parsed, perr := ParsePacket(packet)
	tr.mu.Lock()
	peer := tr.peers[data.DestinationHash(*to)]
	if perr == nil {
		tr.sent = append(tr.sent, parsed)
	}
	hook := tr.hook
	tr.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("loop: no manager for destination")
	}

	gz, err := CompressPayload(packet, ProtoStreaming, fromPort, toPort)
	if err != nil {
		return err
	}
	var drop bool
	var delay time.Duration
	if perr == nil && hook != nil {
		drop, delay = hook(parsed)
	}
	if drop {
		return nil
	}
	go func() {
		if delay > 0 {
			time.Sleep(delay)
		}
		peer.HandleMessage(gz)
	}()
	return nil
}

// newPair creates two connected managers (A the client, B the server).
func newPair(t *testing.T, opts Options) (mA, mB *Manager, destA, destB *data.Destination, tr *loopTransport) {
	t.Helper()
	var privA, privB ed25519.PrivateKey
	destA, privA = testDest(t, 1)
	destB, privB = testDest(t, 2)
	tr = newLoopTransport()
	mA = NewManager(destA, privA, tr, opts)
	mB = NewManager(destB, privB, tr, opts)
	tr.add(mA)
	tr.add(mB)
	return mA, mB, destA, destB, tr
}

func TestStreamLoopbackEcho(t *testing.T) {
	mA, mB, _, destB, _ := newPair(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		s, err := mB.Accept(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s) // echo server: EOF when the client closes
		s.Close()
	}()

	s, err := mA.Dial(ctx, destB, 80)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the quick brown fox jumps over the lazy dog")
	if _, err := s.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.WaitClosed(ctx); err != nil {
		t.Fatalf("wait closed: %v", err)
	}
}

func TestStreamLargeTransfer(t *testing.T) {
	mA, mB, _, destB, _ := newPair(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const total = 200 * 1024
	payload := make([]byte, total)
	rand.Read(payload)

	go func() {
		s, err := mB.Accept(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	s, err := mA.Dial(ctx, destB, 80)
	if err != nil {
		t.Fatal(err)
	}
	// Real clients half-close: send the request, then close our write
	// side, then drain the response to EOF.
	go func() {
		s.SetDeadline(time.Now().Add(45 * time.Second))
		if _, err := s.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
		s.Close() // CLOSE — the echo server sees EOF and closes back
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != total {
		t.Fatalf("read %d bytes, want %d", len(got), total)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if err := s.WaitClosed(ctx); err != nil {
		t.Fatalf("wait closed: %v", err)
	}
}

// Drops the first copy of two data packets and delays a third so later
// packets overtake it: exercises nacks, fast/full retransmission and
// out-of-order reassembly.
func TestStreamLossAndReorder(t *testing.T) {
	mA, mB, _, destB, tr := newPair(t, Options{InitialRTO: 250 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var mu sync.Mutex
	dropped := map[int64]int{}
	delayed := map[int64]bool{}
	tr.mu.Lock()
	tr.hook = func(p *Packet) (bool, time.Duration) {
		if len(p.Payload) == 0 {
			return false, 0 // only touch data packets
		}
		mu.Lock()
		defer mu.Unlock()
		if p.SequenceNum >= 1 && p.SequenceNum <= 2 && dropped[p.SequenceNum] == 0 {
			dropped[p.SequenceNum]++
			return true, 0 // vanish
		}
		if p.SequenceNum == 4 && !delayed[4] {
			delayed[4] = true
			return false, 500 * time.Millisecond // overtake me
		}
		return false, 0
	}
	tr.mu.Unlock()

	const total = 32 * 1024
	payload := make([]byte, total)
	rand.Read(payload)

	go func() {
		s, err := mB.Accept(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	s, err := mA.Dial(ctx, destB, 80)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		s.SetDeadline(time.Now().Add(45 * time.Second))
		if _, err := s.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
		s.Close() // CLOSE — the echo server sees EOF and closes back
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch after loss: got %d bytes", len(got))
	}
	if err := s.WaitClosed(ctx); err != nil {
		t.Fatalf("wait closed: %v", err)
	}
}

func TestStreamReset(t *testing.T) {
	mA, mB, _, destB, _ := newPair(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		s, err := mB.Accept(ctx)
		if err != nil {
			return
		}
		buf := make([]byte, 16)
		s.SetReadDeadline(time.Now().Add(3 * time.Second))
		s.Read(buf) // wait for client data
		// Server aborts: a signed RESET addressed to the client stream.
		r := &Packet{
			SendStreamID:    s.sendStreamID,    // the client's receive ID
			ReceiveStreamID: s.receiveStreamID, // our receive ID
			Flags:           FlagReset | FlagSignatureIncluded,
		}
		r.Sign(mB.signPriv)
		mB.sender.SendPacket(cloneDest(s.remote), r.Encode(), s.localPort, s.remotePort)
	}()

	s, err := mA.Dial(ctx, destB, 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(buf); err != ErrReset {
		t.Fatalf("read after reset: %v, want %v", err, ErrReset)
	}
	if err := s.WaitClosed(ctx); err != ErrReset {
		t.Fatalf("wait closed: %v, want reset", err)
	}
}

// A forged RESET (signed by a key that is not the peer's) must be
// dropped, not tear down the stream.
func TestStreamResetForged(t *testing.T) {
	mA, mB, _, destB, _ := newPair(t, Options{InitialRTO: 600 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan *Stream, 1)
	go func() {
		s, err := mB.Accept(ctx)
		if err == nil {
			accepted <- s
		}
	}()

	s, err := mA.Dial(ctx, destB, 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	// A third party forges a RESET claiming to be B.
	_, attackerPriv := testDest(t, 9)
	r := &Packet{
		SendStreamID:    s.sendStreamID,
		ReceiveStreamID: s.receiveStreamID,
		Flags:           FlagReset | FlagSignatureIncluded,
	}
	r.Sign(attackerPriv)
	gz, _ := CompressPayload(r.Encode(), ProtoStreaming, 0, 0)
	mA.HandleMessage(gz) // delivered directly to the client

	// The stream must survive: write and read still work.
	if _, err := s.Write([]byte("still alive")); err != nil {
		t.Fatalf("forged reset killed the stream: %v", err)
	}
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := s.Read(make([]byte, 16)); err != ErrTimeout {
		t.Fatalf("expected a read timeout, got %v", err)
	}
	s.Close()
}

// ---- SYN handling ----

// craftSyn builds a client SYN with the anti-spoof nacks derived from
// the given hash.
func craftSyn(t *testing.T, from *data.Destination, priv ed25519.PrivateKey, nackHash data.Hash) *Packet {
	t.Helper()
	p := &Packet{
		ReceiveStreamID: 4242,
		Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded | FlagMaxPacketSize,
		AckThrough:      noAckThrough,
		OptionalFrom:    from,
		OptionalMaxSize: 1730,
	}
	for i := 0; i < 8; i++ {
		p.Nacks = append(p.Nacks, binary.BigEndian.Uint32(nackHash[i*4:]))
	}
	p.Sign(priv)
	return p
}

func TestSynAccepted(t *testing.T) {
	_, mB, destA, destB, _ := newPair(t, Options{})
	destAPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Correct nacks: words of the SERVER's hash.
	syn := craftSyn(t, destA, destAPriv, data.DestinationHash(*destB))
	gz, err := CompressPayload(syn.Encode(), ProtoStreaming, 0, 80)
	if err != nil {
		t.Fatal(err)
	}
	mB.HandleMessage(gz)

	s, err := mB.Accept(ctx)
	if err != nil {
		t.Fatalf("SYN not accepted: %v", err)
	}
	if s.remoteHash != data.DestinationHash(*destA) {
		t.Fatal("wrong remote")
	}
	if s.sendStreamID != 4242 {
		t.Fatalf("sendStreamID %d, want 4242", s.sendStreamID)
	}
	if s.remotePort != 0 || s.localPort != 80 {
		t.Fatalf("ports %d/%d", s.remotePort, s.localPort)
	}
}

func TestSynAntiSpoofRejects(t *testing.T) {
	_, mB, destA, _, tr := newPair(t, Options{})
	destAPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Nacks encoding a hash that is NOT the server's.
	syn := craftSyn(t, destA, destAPriv, data.DestinationHash(*destA))
	gz, _ := CompressPayload(syn.Encode(), ProtoStreaming, 0, 80)
	mB.HandleMessage(gz)

	if _, err := mB.Accept(ctx); err == nil {
		t.Fatal("spoofed SYN accepted")
	}
	// The server must have answered with a RESET.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, p := range tr.sent {
		if p.Flags&FlagReset != 0 {
			return
		}
	}
	t.Fatal("no RESET sent for spoofed SYN")
}

// Unsigned SYNs and SYNs from a mismatched FROM signature are dropped.
func TestSynUnsignedRejected(t *testing.T) {
	_, mB, destA, destB, _ := newPair(t, Options{})
	destAPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Unsigned but otherwise valid.
	syn := craftSyn(t, destA, destAPriv, data.DestinationHash(*destB))
	syn.OptionalSig = nil
	syn.Flags &^= FlagSignatureIncluded
	gz, _ := CompressPayload(syn.Encode(), ProtoStreaming, 0, 80)
	mB.HandleMessage(gz)
	if _, err := mB.Accept(ctx); err == nil {
		t.Fatal("unsigned SYN accepted")
	}
}

// ---- ping/pong ----

func TestEchoPingPong(t *testing.T) {
	mA, mB, destA, _, tr := newPair(t, Options{})
	_ = mA

	// A pings B with an unknown stream ID (a ping is not addressed to a
	// stream); B must answer with a pong echoing the ping ID and payload.
	ping := &Packet{
		SendStreamID: 9999,
		Flags:        FlagEcho | FlagFromIncluded,
		OptionalFrom: destA,
		Payload:      []byte("ping"),
	}
	gz, _ := CompressPayload(ping.Encode(), ProtoStreaming, 0, 0)
	mB.HandleMessage(gz)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		sent := append([]*Packet(nil), tr.sent...)
		tr.mu.Unlock()
		for _, p := range sent {
			if p.Flags&FlagEcho != 0 && p.SendStreamID == 0 &&
				p.ReceiveStreamID == 9999 && string(p.Payload) == "ping" {
				return // pong seen
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no pong recorded for ping 9999")
}

// ---- helpers used by the tests above ----

func TestRecvNacks(t *testing.T) {
	s := &Stream{
		recvHighestReady: 2,
		recvHighest:      7,
		notReady:         map[int64][]byte{4: {}, 6: {}},
	}
	n := s.recvNacksLocked()
	want := []uint32{3, 5}
	if len(n) != len(want) {
		t.Fatalf("nacks %v, want %v", n, want)
	}
	for i := range want {
		if n[i] != want[i] {
			t.Fatalf("nacks %v, want %v", n, want)
		}
	}
}

func TestMessageInputStreamReassembly(t *testing.T) {
	s := &Stream{
		notify:           make(chan struct{}),
		recvHighestReady: -1,
		recvHighest:      -1,
		notReady:         map[int64][]byte{},
	}

	// The SYN consumes sequence 0.
	if !s.messageReceivedLocked(0, nil) {
		t.Fatal("seq 0 should be new")
	}
	// Out of order: 2, 3, then 1 fills the hole.
	if !s.messageReceivedLocked(2, []byte("B")) {
		t.Fatal("seq 2 should be new")
	}
	if len(s.recvBuf) != 0 {
		t.Fatal("data must not be readable yet")
	}
	if !s.messageReceivedLocked(3, []byte("C")) {
		t.Fatal("seq 3 should be new")
	}
	if !s.messageReceivedLocked(1, []byte("A")) {
		t.Fatal("seq 1 should be new")
	}
	if string(s.recvBuf) != "ABC" {
		t.Fatalf("buffer %q", s.recvBuf)
	}
	if s.recvHighestReady != 3 || s.recvHighest != 3 {
		t.Fatalf("ready/highest %d/%d", s.recvHighestReady, s.recvHighest)
	}
	if s.messageReceivedLocked(1, []byte("A")) {
		t.Fatal("duplicate must not be new")
	}
}

package ntcp2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
	"github.com/goose-network/i2p-go/internal/noise"
)

// Protocol constants. Reference: OutboundNTCP2State / EstablishBase.
const (
	// ProtocolName is the NTCP2 Noise protocol name.
	ProtocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
	// NetworkID is the main I2P network (proposal 147 cross-check).
	NetworkID = 2
	// NTCP2Version is the protocol version byte in options1.
	NTCP2Version = 2

	keySize      = 32
	ivSize       = 16
	macSize      = 16
	options1Size = 16
	options2Size = 16
	msg1Size     = keySize + options1Size + macSize // 64
	msg2Size     = keySize + options2Size + macSize // 64
	msg3P1Size   = keySize + macSize                // 48
	options3Size = 12
	blockHdrSize = 3

	padding1Max = 64
	padding3Max = 64
	// MaxSkew is the tolerated clock skew with the peer, in seconds.
	MaxSkew = 60

	// paddingMin/MaxDefault are the padding-range defaults advertised in
	// the message 3 options block.
	paddingMinDefault = 0
	paddingMaxDefault = 1
)

// OutboundConfig carries the inputs to an outbound (Alice) NTCP2
// handshake.
type OutboundConfig struct {
	// BobStatic is the "s" option of Bob's NTCP2 RouterAddress.
	BobStatic [32]byte
	// BobIV is the "i" option of Bob's NTCP2 RouterAddress.
	BobIV [16]byte
	// BobRouterHash is SHA-256 of Bob's RouterIdentity (the AES key).
	BobRouterHash []byte
	// AliceStaticPriv is our NTCP2 static x25519 private key.
	AliceStaticPriv []byte
	// AliceRI is our RouterInfo encoding, sent in message 3.
	AliceRI []byte
	// Network is the network ID written to options1 (default 2).
	Network int
	// Now overrides the clock in tests.
	Now func() time.Time
}

func (c *OutboundConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// outboundHandshake drives the Alice side of the handshake.
// Reference: OutboundNTCP2State.
type outboundHandshake struct {
	hs *noise.HandshakeState
	// The AES-256 key is Bob's router hash; the IV chains from the
	// "i" option (msg1) to the tail of obfuscated X (msg2).
	aesKey  []byte
	aesIV   [16]byte
	aliceRI []byte
	padlen3 int
	network int
	now     func() time.Time
	skew    time.Duration
	// msg3Part2Len is declared in options1 and must match message 3.
	msg3Part2Len int
}

func newOutboundHandshake(cfg *OutboundConfig) (*outboundHandshake, error) {
	if len(cfg.BobRouterHash) != 32 {
		return nil, fmt.Errorf("ntcp2: bob router hash length %d", len(cfg.BobRouterHash))
	}
	// PQ marker convention: for version 2 the high bit of the last byte
	// of Bob's static key must be clear.
	if cfg.BobStatic[31]&0x80 != 0 {
		return nil, errors.New("ntcp2: bad NTCP2 S: high bit set")
	}
	if allZero(cfg.BobStatic[:]) {
		return nil, errors.New("ntcp2: bad NTCP2 S: zero key")
	}
	hs, err := noise.NewHandshakeState(ProtocolName, noise.XK, true, cfg.AliceStaticPriv, cfg.BobStatic[:])
	if err != nil {
		return nil, err
	}
	netID := cfg.Network
	if netID == 0 {
		netID = NetworkID
	}
	o := &outboundHandshake{
		hs:      hs,
		aesKey:  append([]byte(nil), cfg.BobRouterHash...),
		aesIV:   cfg.BobIV,
		aliceRI: cfg.AliceRI,
		padlen3: int(randByte()) % padding3Max,
		network: netID,
		now:     cfg.now,
	}
	// Message 3 part 2 length, including the MAC, declared in options1.
	o.msg3Part2Len = blockHdrSize + 1 + len(o.aliceRI) +
		blockHdrSize + options3Size +
		blockHdrSize + o.padlen3 +
		macSize
	return o, nil
}

// message1 builds the first handshake message: obfuscated X, encrypted
// options1, and padding. Reference: OutboundNTCP2State.prepareOutbound.
func (o *outboundHandshake) message1() []byte {
	// options1: netId, version, padlen1, msg3p2len, zero, timestamp, zero.
	padlen1 := int(randByte()) % padding1Max
	var opts [options1Size]byte
	opts[0] = byte(o.network)
	opts[1] = NTCP2Version
	binary.BigEndian.PutUint16(opts[2:4], uint16(padlen1))
	binary.BigEndian.PutUint16(opts[4:6], uint16(o.msg3Part2Len))
	// opts[6:8] zero
	binary.BigEndian.PutUint32(opts[8:12], uint32((o.now().UnixMilli()+500)/1000))
	// opts[12:16] zero

	// One writeMessage covers X and the encrypted options.
	msg, err := o.hs.WriteMessage(opts[:])
	if err != nil {
		panic("ntcp2: msg1 write: " + err.Error())
	}
	if len(msg) != msg1Size {
		panic(fmt.Sprintf("ntcp2: msg1 length %d", len(msg)))
	}
	// AES-256-CBC obfuscate the ephemeral key X in place.
	if err := Obfuscate(msg[:keySize], o.aesKey, o.aesIV[:]); err != nil {
		panic("ntcp2: " + err.Error())
	}
	// Chain the IV: message 2's obfuscation IV is the last 16 bytes of
	// the obfuscated X.
	copy(o.aesIV[:], msg[keySize-ivSize:keySize])
	out := msg
	if padlen1 > 0 {
		pad := randBytes(padlen1)
		o.hs.MixHash(pad)
		out = append(out, pad...)
	}
	return out
}

// readMessage2 reads and processes message 2 (64-byte header plus
// padding). rtt is the time since message 1 was sent.
// Reference: OutboundNTCP2State.receiveOutbound.
func (o *outboundHandshake) readMessage2(r io.Reader, rtt time.Duration) error {
	msg := make([]byte, msg2Size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return fmt.Errorf("ntcp2: read msg2: %w", err)
	}
	if err := Deobfuscate(msg[:keySize], o.aesKey, o.aesIV[:]); err != nil {
		return err
	}
	opts, err := o.hs.ReadMessage(msg)
	if err != nil {
		return fmt.Errorf("ntcp2: msg2: %w", err)
	}
	if len(opts) != options2Size {
		return fmt.Errorf("ntcp2: options2 length %d", len(opts))
	}
	padlen2 := int(binary.BigEndian.Uint16(opts[2:4]))
	tsB := int64(binary.BigEndian.Uint32(opts[8:12]))
	// Skew in seconds, accounting for half the round trip.
	now := o.now().UnixMilli()
	skew := (now - tsB*1000 - rtt.Milliseconds()/2 + 500) / 1000
	if skew > MaxSkew || skew < -MaxSkew {
		return fmt.Errorf("ntcp2: clock skew %ds exceeds %ds", skew, MaxSkew)
	}
	o.skew = time.Duration(skew) * time.Second
	if padlen2 > 0 {
		pad := make([]byte, padlen2)
		if _, err := io.ReadFull(r, pad); err != nil {
			return fmt.Errorf("ntcp2: read msg2 padding: %w", err)
		}
		o.hs.MixHash(pad)
	}
	return nil
}

// message3 builds the third handshake message: Noise-encrypted static
// key (part 1) and the block payload (part 2) under one writeMessage.
// Reference: OutboundNTCP2State.prepareOutbound3.
func (o *outboundHandshake) message3() []byte {
	payload := o.msg3Blocks()
	// Part 1 (48 bytes) + part 2 (payload + MAC).
	msg, err := o.hs.WriteMessage(payload)
	if err != nil {
		panic("ntcp2: msg3 write: " + err.Error())
	}
	if len(msg) != msg3P1Size+len(payload)+macSize {
		panic(fmt.Sprintf("ntcp2: msg3 length %d", len(msg)))
	}
	return msg
}

// msg3Blocks serializes the message 3 payload: RouterInfo, options,
// and padding blocks. Reference: prepareOutbound3 block list.
func (o *outboundHandshake) msg3Blocks() []byte {
	payload := make([]byte, 0, o.msg3Part2Len-macSize)
	// RouterInfo block: no flooding.
	payload = append(payload, byte(BlockRouterInfo))
	payload = binary.BigEndian.AppendUint16(payload, uint16(1+len(o.aliceRI)))
	payload = append(payload, 0) // flag: do not flood
	payload = append(payload, o.aliceRI...)
	// Options block: padding ranges and delay/dummy defaults.
	var opts [options3Size]byte
	opts[0] = paddingMinDefault
	opts[1] = paddingMaxDefault
	opts[2] = paddingMinDefault
	opts[3] = paddingMaxDefault
	payload = append(payload, byte(BlockOptions))
	payload = binary.BigEndian.AppendUint16(payload, options3Size)
	payload = append(payload, opts[:]...)
	// Padding block: all zeros is fine here.
	payload = append(payload, byte(BlockPadding))
	payload = binary.BigEndian.AppendUint16(payload, uint16(o.padlen3))
	payload = append(payload, make([]byte, o.padlen3)...)
	return payload
}

// establish derives the data-phase keys. Reference: setDataPhase +
// NTCPConnection.finishOutboundEstablishment.
func (o *outboundHandshake) establish(conn net.Conn, reader io.Reader) (*Conn, error) {
	send, recv, err := o.hs.Split()
	if err != nil {
		return nil, err
	}
	sipAB, sipBA := GenerateSipHashKeys(o.hs.ChainingKey(), o.hs.HandshakeHash())
	c := &Conn{
		conn:     conn,
		reader:   reader,
		send:     send,
		recv:     recv,
		sendSip:  newSipState(sipAB),
		recvSip:  newSipState(sipBA),
		peerSkew: o.skew,
		remote:   o.hs.RemoteStatic(),
	}
	return c, nil
}

// GenerateSipHashKeys derives the data-phase SipHash keys from the
// post-split chaining key and handshake hash.
// Reference: OutboundNTCP2State.generateSipHashKeys.
func GenerateSipHashKeys(chainingKey, handshakeHash []byte) (sipAB, sipBA []byte) {
	// ask_master = HKDF(ck, zerolen, "ask")
	askMaster := i2pcrypto.HKDF(chainingKey, nil, "ask")
	// sip_master = HKDF(ask_master, handshakeHash || "siphash", "")
	data := make([]byte, 0, 32+len("siphash"))
	data = append(data, handshakeHash...)
	data = append(data, "siphash"...)
	sipMaster := i2pcrypto.HKDF(askMaster, data, "")
	// sip_ab, sip_ba = HKDF2(sip_master, zerolen, "")
	sipAB, sipBA = i2pcrypto.HKDF2(sipMaster, nil, "")
	return
}

// HandshakeOutbound performs the outbound (Alice) NTCP2 handshake over
// the connected conn and returns the established data-phase connection.
// Reference: OutboundNTCP2State end to end.
func HandshakeOutbound(conn net.Conn, cfg *OutboundConfig) (*Conn, error) {
	o, err := newOutboundHandshake(cfg)
	if err != nil {
		return nil, err
	}
	// -> msg1
	msg1 := o.message1()
	tSent := time.Now()
	if _, err := conn.Write(msg1); err != nil {
		return nil, fmt.Errorf("ntcp2: write msg1: %w", err)
	}
	r := newReader(conn)
	// <- msg2 (+ padding)
	if err := o.readMessage2(r, time.Since(tSent)); err != nil {
		return nil, err
	}
	// -> msg3
	if _, err := conn.Write(o.message3()); err != nil {
		return nil, fmt.Errorf("ntcp2: write msg3: %w", err)
	}
	return o.establish(conn, r)
}

func randByte() byte {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ntcp2: entropy failure: " + err.Error())
	}
	return b[0]
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

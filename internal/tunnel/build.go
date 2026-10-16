// Tunnel building with ECIES short build records and the Short Tunnel
// Build Message (STBM).
//
// Short encrypted build record (218 bytes, proposal 157):
//
//	[0..15]   truncated SHA-256 of the target router's hash
//	[16..47]  ephemeral X25519 public key
//	[48..217] Noise N message: ciphertext + 16-byte MAC
//
// Plaintext inside (154 bytes):
//
//	[0..3]    receive tunnel ID
//	[4..7]    next tunnel ID (0 if none / reply tunnel)
//	[8..39]   next router hash (self if inbound endpoint)
//	[40]      flags: 0x80 = IBGW (unrestricted prev), 0x40 = OBEP
//	[41..42]  unused (zero)
//	[43]      layer encryption type (must be 0)
//	[44..47]  request time (minutes since epoch)
//	[48..51]  expiration (seconds, 600)
//	[52..55]  next message ID (reply message ID at OBEP / IBEP creator)
//	[56..153] options mapping + random padding
//
// Per-hop derived keys (proposal 152, short record):
//
//	reply key  = HKDF(ck, "", "SMTunnelReplyKey")      first output
//	layer key  = HKDF(ck, "", "SMTunnelLayerKey")       after reply-key step
//	IV key     = next chaining key, or "TunnelLayerIVKey" step at OBEP
//	garlic tag = "RGarlicKeyAndTag" step (OBEP only): key + 8-byte tag
//
// Record layering: the creator pre-applies ChaCha20 (zero nonce with
// the slot number in byte 4) with each intermediate hop's reply key, so
// that as the message travels, each hop's re-application cancels one
// layer (BuildMessageGenerator.layeredEncrypt pre-cancels: the creator
// decrypts; hops encrypt with ChaCha20 = its own inverse).
//
// Reply: each hop fills its response slot with a 218-byte
// BuildResponseRecord (ChaChaPoly with the reply key, AD = handshake
// hash, nonce = slot). At the OBEP of a longer tunnel, the whole reply
// travels as an OutboundTunnelBuildReplyMessage garlic-wrapped with the
// derived one-time garlic key. For our builds: 0-hop outbound tunnels
// don't build at all (direct NTCP2 sends), and 1-hop inbound tunnels
// have R=IBGW send the mutated STBM directly back to us over NTCP2
// (replyTunnel=0, replyRouter=our hash, STBM message ID = our reply
// message ID), where we verify our blank IBEP record by SHA-256.
//
// Reference: BuildRequestRecord.java, ShortTunnelBuildMessage.java,
// BuildMessageGenerator.java, BuildMessageProcessor.java,
// BuildResponseRecord.java, BuildHandler.java.
package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2pcrypto"
	"github.com/goose-network/i2p-go/internal/noise"
)

// Short record sizes. Reference: ShortTunnelBuildMessage.java,
// BuildRequestRecord.java.
const (
	ShortRecordSize      = 218
	ShortRecordPlaintext = ShortRecordSize - 16 - 32 - 16 // 154
	BuildPeerSize        = 16
	buildMaxRecords      = 8
)

// Short record plaintext offsets. Reference: BuildRequestRecord.java
// (ECIES short record format: [40] flags, [41:43] unused, [43] layer
// enc type, [44:48] request time, [48:52] expiration, [52:56] next
// message ID, [56:154] options + padding).
const (
	offRecvTunnel   = 0
	offNextTunnel   = 4
	offNextIdent    = 8
	offFlag         = 40
	offLayerEncType = 43
	offReqTime      = 44
	offExpiration   = 48
	offSendMsgID    = 52
	offOptions      = 56
)

// Flag bits. Reference: BuildRequestRecord.java.
const (
	flagUnrestrictedPrev = 1 << 7
	flagOutboundEndpoint = 1 << 6
)

// Build-message defaults. Reference: BuildRequestor.java,
// BuildHandler.java.
const (
	buildExpirationSeconds = 600
)

// HKDF info strings for the short-record chain.
// Reference: BuildRequestRecord.java INFO_1..INFO_4.
const (
	infoSMTunnelReplyKey = "SMTunnelReplyKey"
	infoSMTunnelLayerKey = "SMTunnelLayerKey"
	infoTunnelLayerIVKey = "TunnelLayerIVKey"
	infoRGarlicKeyAndTag = "RGarlicKeyAndTag"
)

// HopKeys are the keys one hop derives from its short build record.
type HopKeys struct {
	ReplyKey []byte // ChaCha20 reply-record key (also ChaChaPoly AEAD key)
	ReplyAD  []byte // 32-byte Noise handshake hash (AD for the reply record)
	LayerKey []byte
	IVKey    []byte
	Garlic   *GarlicReplyKeys // OBEP only
}

// GarlicReplyKeys is the one-time garlic key/tag pair derived at the
// OBEP. Reference: BuildRequestRecord.readGarlicKeys.
type GarlicReplyKeys struct {
	Key []byte
	Tag []byte // 8 bytes
}

// HopConfig is one hop's derived configuration, kept by the creator.
// For our 1-hop inbound tunnels this describes R = the IBGW.
// Reference: BuildMessageGenerator.createRecord (short-record branch
// saving derived keys).
type HopConfig struct {
	// Peer is the hop's router hash.
	Peer data.Hash
	// ReceiveTunnelID is the tunnel ID the hop receives on.
	ReceiveTunnelID uint32
	// SendTunnelID is the tunnel ID at the hop's next hop.
	SendTunnelID uint32
	// SendTo is the next hop's hash.
	SendTo data.Hash
	// Keys derived from the short record.
	Keys *HopKeys
}

// encodeProperties serializes a small options mapping (2-byte count,
// then per entry: 2-byte key length, key, 2-byte value length, value;
// sorted by key). Reference: DataHelper.writeProperties. nil options
// encode as an empty mapping.
func encodeProperties(props map[string]string) []byte {
	if len(props) == 0 {
		return []byte{0, 0}
	}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []byte
	out = binary.BigEndian.AppendUint16(out, uint16(len(keys)))
	for _, k := range keys {
		out = binary.BigEndian.AppendUint16(out, uint16(len(k)))
		out = append(out, k...)
		v := props[k]
		out = binary.BigEndian.AppendUint16(out, uint16(len(v)))
		out = append(out, v...)
	}
	return out
}

// decodeProperties parses an options mapping.
func decodeProperties(b []byte) (map[string]string, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("tunnel: short properties")
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	props := make(map[string]string)
	for i := 0; i < n; i++ {
		if len(b) < 2 {
			return nil, fmt.Errorf("tunnel: short property key len")
		}
		kl := int(binary.BigEndian.Uint16(b[0:2]))
		b = b[2:]
		if len(b) < kl+2 {
			return nil, fmt.Errorf("tunnel: short property key")
		}
		k := string(b[:kl])
		b = b[kl:]
		vl := int(binary.BigEndian.Uint16(b[0:2]))
		b = b[2:]
		if len(b) < vl {
			return nil, fmt.Errorf("tunnel: short property value")
		}
		props[k] = string(b[:vl])
		b = b[vl:]
	}
	return props, nil
}

// shortRecord holds one hop's plaintext build record.
type shortRecord struct {
	recvTunnel uint32
	nextTunnel uint32
	nextIdent  [32]byte
	isInGW     bool
	isOutEnd   bool
	nextMsgID  uint32
	props      map[string]string
}

// encryptShortRecord Noise-encrypts one hop's record and derives its
// keys. Returns the 218-byte encrypted record.
// Reference: BuildRequestRecord.encryptECIESRecord.
func encryptShortRecord(rec *shortRecord, peerKey []byte, peerHash data.Hash, now func() time.Time) ([]byte, *HopKeys, error) {
	// Serialize the plaintext.
	plain := make([]byte, ShortRecordPlaintext)
	binary.BigEndian.PutUint32(plain[offRecvTunnel:], rec.recvTunnel)
	binary.BigEndian.PutUint32(plain[offNextTunnel:], rec.nextTunnel)
	copy(plain[offNextIdent:], rec.nextIdent[:])
	if rec.isInGW {
		plain[offFlag] |= flagUnrestrictedPrev
	} else if rec.isOutEnd {
		plain[offFlag] |= flagOutboundEndpoint
	}
	plain[offLayerEncType] = 0
	// Request time in minutes, with up to 2048 ms of backwards jitter
	// to prevent hop identification at the top of a minute.
	// Reference: BuildRequestRecord ECIES short constructor.
	t := now().Add(-time.Duration(binary.BigEndian.Uint32(randomBytes(4))%2048) * time.Millisecond)
	minutes := t.Unix() / 60
	binary.BigEndian.PutUint32(plain[offReqTime:], uint32(minutes))
	binary.BigEndian.PutUint32(plain[offExpiration:], buildExpirationSeconds)
	binary.BigEndian.PutUint32(plain[offSendMsgID:], rec.nextMsgID)
	props := encodeProperties(rec.props)
	copy(plain[offOptions:], props)
	// Randomize any remaining space.
	rand.Read(plain[offOptions+len(props):])

	// Noise N message with the peer's static key as the destination.
	state, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, true, nil, peerKey)
	if err != nil {
		return nil, nil, err
	}
	msg, err := state.WriteMessage(plain)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, ShortRecordSize)
	copy(out[:BuildPeerSize], peerHash[:BuildPeerSize])
	copy(out[BuildPeerSize:], msg)

	// Derive the hop's keys from the post-handshake chaining key.
	keys := &HopKeys{
		ReplyAD: append([]byte(nil), state.HandshakeHash()...),
	}
	newck1, crk := i2pcrypto.HKDF2(state.ChainingKey(), nil, infoSMTunnelReplyKey)
	keys.ReplyKey = crk
	newck2, dlk := i2pcrypto.HKDF2(newck1, nil, infoSMTunnelLayerKey)
	keys.LayerKey = dlk
	if rec.isOutEnd {
		newck3, divk := i2pcrypto.HKDF2(newck2, nil, infoTunnelLayerIVKey)
		keys.IVKey = divk
		newck4, dgk := i2pcrypto.HKDF2(newck3, nil, infoRGarlicKeyAndTag)
		keys.Garlic = &GarlicReplyKeys{Key: dgk, Tag: newck4[:8]}
	} else {
		keys.IVKey = newck2
	}
	return out, keys, nil
}

// protocolNameN is the Noise N pattern name for build records.
// Reference: NoiseInit protocolName3 (also used by garlic).
const protocolNameN = "Noise_N_25519_ChaChaPoly_SHA256"

// decryptShortRecord is the responder side of encryptShortRecord: it
// Noise-decrypts a record addressed to us and derives our hop's keys.
// The caller MUST have checked the 16-byte hash prefix first.
// Reference: BuildRequestRecord decrypting constructor (ECIES branch).
func decryptShortRecord(rec []byte, ourPriv []byte) (*shortRecord, *HopKeys, error) {
	if len(rec) != ShortRecordSize {
		return nil, nil, fmt.Errorf("tunnel: record size %d", len(rec))
	}
	state, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, false, ourPriv, nil)
	if err != nil {
		return nil, nil, err
	}
	plain, err := state.ReadMessage(rec[BuildPeerSize:])
	if err != nil {
		return nil, nil, err
	}
	if len(plain) != ShortRecordPlaintext {
		return nil, nil, fmt.Errorf("tunnel: record plaintext size %d", len(plain))
	}

	out := &shortRecord{
		recvTunnel: binary.BigEndian.Uint32(plain[offRecvTunnel:]),
		nextTunnel: binary.BigEndian.Uint32(plain[offNextTunnel:]),
		isInGW:     plain[offFlag]&flagUnrestrictedPrev != 0,
		isOutEnd:   plain[offFlag]&flagOutboundEndpoint != 0,
		nextMsgID:  binary.BigEndian.Uint32(plain[offSendMsgID:]),
	}
	copy(out.nextIdent[:], plain[offNextIdent:offNextIdent+32])
	props, err := decodeProperties(plain[offOptions:])
	if err == nil {
		out.props = props
	}

	keys := &HopKeys{
		ReplyAD: append([]byte(nil), state.HandshakeHash()...),
	}
	// Same HKDF chain as the creator. Reference:
	// BuildRequestRecord INFO_1..INFO_4 steps.
	newck1, crk := i2pcrypto.HKDF2(state.ChainingKey(), nil, infoSMTunnelReplyKey)
	keys.ReplyKey = crk
	newck2, dlk := i2pcrypto.HKDF2(newck1, nil, infoSMTunnelLayerKey)
	keys.LayerKey = dlk
	if out.isOutEnd {
		newck3, divk := i2pcrypto.HKDF2(newck2, nil, infoTunnelLayerIVKey)
		keys.IVKey = divk
		newck4, dgk := i2pcrypto.HKDF2(newck3, nil, infoRGarlicKeyAndTag)
		keys.Garlic = &GarlicReplyKeys{Key: dgk, Tag: newck4[:8]}
	} else {
		keys.IVKey = newck2
	}
	return out, keys, nil
}

// randomBytes returns n random bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// chacha20Block runs the ChaCha20 block function. Used for STBM
// record layering, which encrypts exactly one block (218 bytes) per
// record. Reference: BuildMessageProcessor/BuildMessageGenerator
// ChaCha20.encrypt(key, iv, data...) with iv[4] = slot.
func chacha20Block(key []byte, counter uint32, data []byte) {
	// ChaCha20 with a 12-byte nonce: 4 zero bytes + counter (LE) + 7
	// zero bytes — matching Java's iv[4] = (byte) recordNum layout.
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[4:8], counter)
	chachaXOR(key, nonce, data, 1)
}

// chachaXOR XORs data with the ChaCha20 keystream starting at block
// counter 1 (the first data block; Java's ChaCha20.encrypt uses
// counter values equal to the block index).
func chachaXOR(key, nonce []byte, data []byte, initialCounter uint32) {
	// Use the golang.org/x/crypto chacha20 (our only external dep).
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	c.SetCounter(initialCounter)
	c.XORKeyStream(data, data)
}

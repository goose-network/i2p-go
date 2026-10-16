// Package streaming implements the I2P streaming protocol: reliable,
// ordered, flow-controlled byte streams over I2P's best-effort datagram
// delivery — the protocol behind eepsite connections, exposed to the
// user through the SOCKS5 proxy.
//
// Wire format (Packet.java writePacket):
//
//	[4B sendStreamId][4B receiveStreamId][4B sequenceNum][4B ackThrough]
//	[1B nackCount][4B × nacks][1B resendDelay][2B flags][2B optionSize]
//	[options][payload]
//
// Options, in order: delay (2B) → FROM destination → max packet size
// (2B) → signature. The signature (when present) covers the whole
// packet with the signature bytes zeroed.
//
// Stream-ID semantics: the receiveStreamId field of a packet carries
// the SENDER's own receive ID; the sendStreamId field carries the
// RECEIVER's receive ID (0 until learned, i.e. in the client's SYN).
// Inbound packets are dispatched by looking up our connection whose
// receive ID equals the packet's sendStreamId, falling back to the
// connection whose send ID (the peer's receive ID, learned from the
// SYN-ACK) equals the packet's receiveStreamId.
//
// Reference: apps/streaming/java/src/net/i2p/client/streaming/impl/ in
// the Java router (../i2p.i2p).
package streaming

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// Packet flag bits. Reference: Packet.java FLAG_*.
const (
	FlagSYN                uint16 = 1 << 0
	FlagClose              uint16 = 1 << 1
	FlagReset              uint16 = 1 << 2
	FlagSignatureIncluded  uint16 = 1 << 3
	FlagSignatureRequested uint16 = 1 << 4
	FlagFromIncluded       uint16 = 1 << 5
	FlagDelayRequested     uint16 = 1 << 6
	FlagMaxPacketSize      uint16 = 1 << 7
	FlagProfileInteractive uint16 = 1 << 8
	FlagEcho               uint16 = 1 << 9
	FlagNoAck              uint16 = 1 << 10
	FlagSignatureOffline   uint16 = 1 << 11
)

// MaxPayloadSize is the largest payload a single packet may carry.
// Reference: Packet.MAX_PAYLOAD_SIZE.
const MaxPayloadSize = 32 * 1024

// packetHeaderLen is the fixed part of the header (without nacks or
// options): 4×4B ids + 1B nackCount + 1B resendDelay + 2B flags +
// 2B optionSize.
const packetHeaderLen = 4 + 4 + 4 + 4 + 1 + 1 + 2 + 2

// noAckThrough marks "this packet acks nothing"; it is written as 0 on
// the wire (Java writePacket: `_ackThrough > 0 ? _ackThrough : 0`).
const noAckThrough = int64(-1)

// Packet is one streaming packet. SequenceNum and AckThrough use the
// Java -1 convention for "unset".
type Packet struct {
	SendStreamID    uint32
	ReceiveStreamID uint32
	SequenceNum     int64
	AckThrough      int64
	Nacks           []uint32
	ResendDelay     uint8
	Flags           uint16

	OptionalDelay   uint16
	OptionalFrom    *data.Destination
	OptionalMaxSize uint16
	OptionalSig     []byte

	// Offline signing block (FlagSignatureOffline): the destination's
	// real key authorizes a transient key until TransientExpires, and
	// the transient key signs the packet. Common for long-lived sites
	// (zzz.i2p) whose private key lives offline.
	TransientExpires uint32 // unix seconds
	TransientSigType data.SigType
	TransientSPK     []byte // typed by TransientSigType
	OfflineSignature []byte // by the FROM's (real) key

	Payload []byte
}

func wireU32(v int64) uint32 {
	if v > 0 {
		return uint32(v)
	}
	return 0
}

// Encode serializes the packet including any signature.
func (p *Packet) Encode() []byte { return p.encode(0) }

// encode writes the packet; fakeSigLen > 0 writes that many zero bytes
// in place of the signature (the form that gets signed).
func (p *Packet) encode(fakeSigLen int) []byte {
	optionSize := 0
	if p.Flags&FlagDelayRequested != 0 {
		optionSize += 2
	}
	if p.Flags&FlagFromIncluded != 0 {
		var tmp []byte
		tmp = p.OptionalFrom.WriteTo(tmp)
		optionSize += len(tmp)
	}
	if p.Flags&FlagMaxPacketSize != 0 {
		optionSize += 2
	}
	if p.Flags&FlagSignatureOffline != 0 {
		optionSize += 6 + len(p.TransientSPK) + len(p.OfflineSignature)
	}
	if p.Flags&FlagSignatureIncluded != 0 {
		if fakeSigLen > 0 {
			optionSize += fakeSigLen
		} else {
			optionSize += len(p.OptionalSig)
		}
	}

	total := packetHeaderLen + 4*len(p.Nacks) + optionSize + len(p.Payload)
	buf := make([]byte, 0, total)
	buf = binary.BigEndian.AppendUint32(buf, p.SendStreamID)
	buf = binary.BigEndian.AppendUint32(buf, p.ReceiveStreamID)
	buf = binary.BigEndian.AppendUint32(buf, wireU32(p.SequenceNum))
	buf = binary.BigEndian.AppendUint32(buf, wireU32(p.AckThrough))
	buf = append(buf, byte(len(p.Nacks)))
	for _, n := range p.Nacks {
		buf = binary.BigEndian.AppendUint32(buf, n)
	}
	buf = append(buf, p.ResendDelay)
	buf = binary.BigEndian.AppendUint16(buf, p.Flags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(optionSize))
	if p.Flags&FlagDelayRequested != 0 {
		buf = binary.BigEndian.AppendUint16(buf, p.OptionalDelay)
	}
	if p.Flags&FlagFromIncluded != 0 {
		buf = p.OptionalFrom.WriteTo(buf)
	}
	if p.Flags&FlagMaxPacketSize != 0 {
		max := p.OptionalMaxSize
		if max == 0 {
			max = defaultMaxPacketSize
		}
		buf = binary.BigEndian.AppendUint16(buf, max)
	}
	if p.Flags&FlagSignatureOffline != 0 {
		buf = binary.BigEndian.AppendUint32(buf, p.TransientExpires)
		buf = binary.BigEndian.AppendUint16(buf, uint16(p.TransientSigType))
		buf = append(buf, p.TransientSPK...)
		buf = append(buf, p.OfflineSignature...)
	}
	if p.Flags&FlagSignatureIncluded != 0 {
		if fakeSigLen > 0 {
			buf = append(buf, make([]byte, fakeSigLen)...)
		} else {
			buf = append(buf, p.OptionalSig...)
		}
	}
	buf = append(buf, p.Payload...)
	return buf
}

// ParsePacket parses one packet from b. The payload and signature alias
// b. For signatures carried without a FROM the length is guessed from
// the remaining option bytes (Java does the same and reinterprets the
// bytes when verifying).
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < packetHeaderLen {
		return nil, fmt.Errorf("streaming: short packet %d", len(b))
	}
	p := &Packet{}
	p.SendStreamID = binary.BigEndian.Uint32(b[0:])
	p.ReceiveStreamID = binary.BigEndian.Uint32(b[4:])
	p.SequenceNum = int64(binary.BigEndian.Uint32(b[8:]))
	p.AckThrough = int64(binary.BigEndian.Uint32(b[12:]))
	off := 16
	n := int(b[off])
	off++
	if n > 255 || len(b) < off+4*n+5 {
		return nil, fmt.Errorf("streaming: truncated nacks")
	}
	if n > 0 {
		p.Nacks = make([]uint32, n)
		for i := 0; i < n; i++ {
			p.Nacks[i] = binary.BigEndian.Uint32(b[off:])
			off += 4
		}
	}
	p.ResendDelay = b[off]
	off++
	p.Flags = binary.BigEndian.Uint16(b[off:])
	off += 2
	optionSize := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+optionSize > len(b) {
		return nil, fmt.Errorf("streaming: options overflow %d+%d > %d", off, optionSize, len(b))
	}
	p.Payload = b[off+optionSize:]
	if len(p.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("streaming: payload %d exceeds max", len(p.Payload))
	}
	optEnd := off + optionSize
	if p.Flags&FlagDelayRequested != 0 {
		if off+2 > optEnd {
			return nil, fmt.Errorf("streaming: short delay option")
		}
		p.OptionalDelay = binary.BigEndian.Uint16(b[off:])
		off += 2
	}
	if p.Flags&FlagFromIncluded != 0 {
		from, rest, err := data.ReadDestination(b[off:optEnd])
		if err != nil {
			return nil, fmt.Errorf("streaming: bad FROM: %w", err)
		}
		off = optEnd - len(rest)
		p.OptionalFrom = &from
	}
	if p.Flags&FlagMaxPacketSize != 0 {
		if off+2 > optEnd {
			return nil, fmt.Errorf("streaming: short max-size option")
		}
		p.OptionalMaxSize = binary.BigEndian.Uint16(b[off:])
		off += 2
	}
	if p.Flags&FlagSignatureOffline != 0 {
		// [expires 4s][sig type 2][typed SPK][offline signature]. The
		// offline signature's length is fixed by the FROM's sig type
		// (the real key that made it). Reference: Packet.readBytes.
		if off+6 > optEnd {
			return nil, fmt.Errorf("streaming: short offline block")
		}
		p.TransientExpires = binary.BigEndian.Uint32(b[off:])
		p.TransientSigType = data.SigType(binary.BigEndian.Uint16(b[off+4:]))
		off += 6
		spkLen := p.TransientSigType.PubkeyLen()
		if spkLen < 0 || off+spkLen > optEnd {
			return nil, fmt.Errorf("streaming: bad transient key type %d", p.TransientSigType)
		}
		p.TransientSPK = b[off : off+spkLen]
		off += spkLen
		offLen := 64
		if p.OptionalFrom != nil {
			if l := sigLenFor(p.OptionalFrom.SigType); l > 0 {
				offLen = l
			}
		}
		if off+offLen > optEnd {
			return nil, fmt.Errorf("streaming: short offline signature")
		}
		p.OfflineSignature = b[off : off+offLen]
		off += offLen
	}
	if p.Flags&FlagSignatureIncluded != 0 {
		sigLen := optEnd - off
		sigType := data.SigEdDSA_SHA512_Ed25519
		if p.OptionalFrom != nil {
			// The FROM's sig type fixes the length — unless the packet
			// is signed offline, where the transient key's type does
			// (Java: Packet.readBytes FLAG_SIGNATURE_INCLUDED).
			sigType = p.OptionalFrom.SigType
			if p.Flags&FlagSignatureOffline != 0 {
				sigType = p.TransientSigType
			}
			switch sigType {
			case data.SigEdDSA_SHA512_Ed25519, data.SigRedDSA_SHA512_Ed25519:
				if sigLen < 64 {
					return nil, fmt.Errorf("streaming: short signature %d", sigLen)
				}
				sigLen = 64
			case data.SigDSA_SHA1:
				if sigLen < 40 {
					return nil, fmt.Errorf("streaming: short signature %d", sigLen)
				}
				sigLen = 40
			}
		} else if sigLen != 64 && sigLen != 40 {
			// Unknown combination: take what is there; verification will
			// fail if the length is wrong.
			if sigLen < 40 {
				return nil, fmt.Errorf("streaming: short signature %d", sigLen)
			}
		}
		p.OptionalSig = b[off : off+sigLen]
		off += sigLen
	}
	return p, nil
}

// Sign signs the packet in place with our destination's Ed25519 key,
// setting FLAG_SIGNATURE_INCLUDED. Reference: PacketLocal.writeSignedPacket
// — sign the whole packet with the signature area zeroed.
func (p *Packet) Sign(priv ed25519.PrivateKey) {
	p.Flags |= FlagSignatureIncluded
	buf := p.encode(ed25519.SignatureSize)
	p.OptionalSig = ed25519.Sign(priv, buf)
}

// Verify checks the packet signature. spk is the expected signer's
// public key — the FROM's key when the packet carries a FROM (Java:
// verifySignature prefers the FROM), otherwise the caller's known
// remote key. An offline-signed packet is verified in two steps: the
// destination's real key must have authorized the transient key (the
// offline signature over expires + type + SPK, unexpired), and the
// transient key must have signed the packet.
func (p *Packet) Verify(spk ed25519.PublicKey) bool {
	if p.Flags&FlagSignatureIncluded == 0 || len(p.OptionalSig) != ed25519.SignatureSize {
		return false
	}
	if p.OptionalFrom != nil {
		if p.OptionalFrom.SigType != data.SigEdDSA_SHA512_Ed25519 {
			return false
		}
		spk = ed25519.PublicKey(p.OptionalFrom.SigningKey)
	}
	if len(spk) != ed25519.PublicKeySize {
		return false
	}
	if p.Flags&FlagSignatureOffline != 0 {
		if uint64(p.TransientExpires) < uint64(time.Now().Unix()) {
			return false // transient key expired
		}
		var block []byte
		block = binary.BigEndian.AppendUint32(block, p.TransientExpires)
		block = binary.BigEndian.AppendUint16(block, uint16(p.TransientSigType))
		block = append(block, p.TransientSPK...)
		if !ed25519.Verify(spk, block, p.OfflineSignature) {
			return false // transient key not authorized by the real key
		}
		spk = ed25519.PublicKey(p.TransientSPK)
		if len(spk) != ed25519.PublicKeySize {
			return false
		}
	}
	buf := p.encode(ed25519.SignatureSize)
	return ed25519.Verify(spk, buf, p.OptionalSig)
}

// sigLenFor returns the encoded signature length for a sig type
// (mirrors data's unexported helper; only the types the streaming
// layer can verify are listed).
func sigLenFor(t data.SigType) int {
	switch t {
	case data.SigDSA_SHA1:
		return 40
	case data.SigEdDSA_SHA512_Ed25519, data.SigRedDSA_SHA512_Ed25519:
		return 64
	}
	return -1
}

// String renders a compact one-line description for logs.
func (p *Packet) String() string {
	s := fmt.Sprintf("pkt{send=%d recv=%d seq=%d ack=%d n=%d fl=%04x",
		p.SendStreamID, p.ReceiveStreamID, p.SequenceNum, p.AckThrough, len(p.Nacks), p.Flags)
	if p.Flags&FlagSYN != 0 {
		s += " SYN"
	}
	if p.Flags&FlagClose != 0 {
		s += " CLOSE"
	}
	if p.Flags&FlagReset != 0 {
		s += " RESET"
	}
	if p.Flags&FlagNoAck != 0 {
		s += " NOACK"
	}
	return s + fmt.Sprintf(" len=%d}", len(p.Payload))
}

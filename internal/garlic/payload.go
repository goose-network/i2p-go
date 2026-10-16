// RatchetPayload block structure: each block is a 3-byte header
// (type, 2-byte length) followed by data. The payload of every
// NS/NSR/ES garlic message is a sequence of these blocks.
//
// This file ports the payload half of RatchetPayload.java and the
// createPayload/calculatePadding logic from ECIESAEADEngine.java.
package garlic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"math/big"
	"time"
)

// Payload block types. Reference: RatchetPayload.java constants.
const (
	BlockDateTime    = 0
	BlockSessionID   = 1
	BlockTermination = 4
	BlockOptions     = 5
	BlockMsgNum      = 6
	BlockNextKey     = 7
	BlockAck         = 8
	BlockAckRequest  = 9
	BlockGarlic      = 11
	BlockPadding     = 254
)

// BlockHeaderSize is the 3-byte block header (type + 2-byte length).
const BlockHeaderSize = 3

// NextSessionKey is a ratchet next key announcement (NextKey block).
// Reference: NextSessionKey.java.
type NextSessionKey struct {
	Key       []byte // 32 bytes or nil (flag-only request)
	ID        int    // 0-65535
	IsReverse bool
	IsRequest bool
}

// Ack is one entry of an Ack block: a count of messages received for
// a tagset ID.
type Ack struct {
	TagSetID int
	N        int
}

// ParsedPayload is the result of decoding a RatchetPayload. Fields
// are zero if the corresponding block was absent.
type ParsedPayload struct {
	DateTime     int64 // unix seconds
	Options      []byte
	Termination  int // -1 if absent
	PN           int // -1 if absent
	NextKeys     []NextSessionKey
	Acks         []Ack
	AckRequested bool
	Cloves       []*Clove
	PaddingLen   int
	FrameLen     int
}

// ProcessPayload decodes a sequence of ratchet payload blocks, filling
// a ParsedPayload. The rules: nothing may follow a Padding block, and
// only Padding may follow a Termination block; several block types
// are illegal inside NS/NSR handshake payloads.
// Reference: RatchetPayload.processPayload.
func ProcessPayload(payload []byte, isHandshake bool) (*ParsedPayload, error) {
	rv := &ParsedPayload{Termination: -1, PN: -1, FrameLen: len(payload)}
	gotPadding := false
	gotTermination := false
	i := 0
	for i < len(payload) {
		typ := payload[i]
		if gotPadding {
			return nil, fmt.Errorf("garlic: block after padding: %d", typ)
		}
		if gotTermination && typ != BlockPadding {
			return nil, fmt.Errorf("garlic: block after termination: %d", typ)
		}
		if len(payload)-i < 3 {
			return nil, fmt.Errorf("garlic: truncated block header at %d", i)
		}
		ln := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		i += 3
		if ln > len(payload)-i {
			return nil, fmt.Errorf("garlic: block type %d length %d runs over frame of %d", typ, ln, len(payload))
		}
		data := payload[i : i+ln]
		switch typ {
		case BlockDateTime:
			if ln != 4 {
				return nil, fmt.Errorf("garlic: bad DateTime length %d", ln)
			}
			// The wire value is seconds; gotDateTime multiplies by 1000.
			rv.DateTime = int64(binary.BigEndian.Uint32(data)) * 1000
		case BlockOptions:
			rv.Options = append([]byte(nil), data...)
		case BlockGarlic:
			clove, err := DecodeCloveRatchet(data)
			if err != nil {
				return nil, err
			}
			rv.Cloves = append(rv.Cloves, clove)
		case BlockNextKey:
			if ln != 3 && ln != 35 {
				return nil, fmt.Errorf("garlic: bad NextKey length %d", ln)
			}
			nk := NextSessionKey{
				IsReverse: data[0]&0x02 != 0,
				IsRequest: data[0]&0x04 != 0,
				ID:        int(binary.BigEndian.Uint16(data[1:3])),
			}
			if data[0]&0x01 != 0 {
				if ln != 35 {
					return nil, fmt.Errorf("garlic: NextKey missing key data")
				}
				nk.Key = append([]byte(nil), data[3:35]...)
			}
			rv.NextKeys = append(rv.NextKeys, nk)
		case BlockAck:
			if ln < 4 || ln%4 != 0 {
				return nil, fmt.Errorf("garlic: bad Ack length %d", ln)
			}
			for j := 0; j+4 <= ln; j += 4 {
				rv.Acks = append(rv.Acks, Ack{
					TagSetID: int(binary.BigEndian.Uint16(data[j : j+2])),
					N:        int(binary.BigEndian.Uint16(data[j+2 : j+4])),
				})
			}
		case BlockAckRequest:
			if ln < 1 {
				return nil, fmt.Errorf("garlic: bad AckRequest length %d", ln)
			}
			rv.AckRequested = true
		case BlockTermination:
			if isHandshake {
				return nil, fmt.Errorf("garlic: termination in handshake")
			}
			if ln < 1 {
				return nil, fmt.Errorf("garlic: bad Termination length %d", ln)
			}
			rv.Termination = int(data[0])
			gotTermination = true
		case BlockMsgNum:
			if isHandshake {
				return nil, fmt.Errorf("garlic: PN in handshake")
			}
			if ln < 2 {
				return nil, fmt.Errorf("garlic: bad PN length %d", ln)
			}
			rv.PN = int(binary.BigEndian.Uint16(data))
		case BlockPadding:
			gotPadding = true
			rv.PaddingLen = ln
		default:
			if isHandshake {
				return nil, fmt.Errorf("garlic: illegal block in handshake: %d", typ)
			}
			// Unknown blocks are skipped.
		}
		i += ln
	}
	return rv, nil
}

// Padding size boundaries we try not to exceed: one, two, or three
// tunnel messages. Reference: ECIESAEADEngine createPadding and
// streaming ConnectionOptions for the math.
const (
	padB1  = 944
	padB2  = 1936
	padB3  = 2932
	maxPad = 16
)

// buildBlock appends one block (header + data) to buf.
func buildBlock(buf []byte, typ int, data []byte) []byte {
	var hdr [3]byte
	hdr[0] = byte(typ)
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(data)))
	buf = append(buf, hdr[:]...)
	return append(buf, data...)
}

// buildPayload assembles the payload for an NS, NSR, or ES message:
// DateTime, NextKey(s), Garlic cloves, AckRequest, Acks, then Padding.
// expiration is the CloveSet expiration (nonzero adds a DateTime
// block); overhead is NS_OVERHEAD (96), NSR_OVERHEAD (72), or
// ES_OVERHEAD (24), used for the padding calculation.
// Reference: ECIESAEADEngine.createPayload.
func buildPayload(cloves []*Clove, expiration time.Time, ackreq bool,
	nextKeys []NextSessionKey, acks []Ack, overhead int) []byte {
	var blocks []byte
	if !expiration.IsZero() {
		var dt [4]byte
		binary.BigEndian.PutUint32(dt[:], uint32(expiration.UnixMilli()/1000))
		blocks = buildBlock(blocks, BlockDateTime, dt[:])
	}
	for i := range nextKeys {
		nk := &nextKeys[i]
		if nk.Key != nil {
			data := make([]byte, 35)
			data[0] = 0x01
			if nk.IsReverse {
				data[0] |= 0x02
			}
			if nk.IsRequest {
				data[0] |= 0x04
			}
			binary.BigEndian.PutUint16(data[1:3], uint16(nk.ID))
			copy(data[3:], nk.Key)
			blocks = buildBlock(blocks, BlockNextKey, data)
		} else {
			data := make([]byte, 3)
			if nk.IsReverse {
				data[0] |= 0x02
			}
			if nk.IsRequest {
				data[0] |= 0x04
			}
			binary.BigEndian.PutUint16(data[1:3], uint16(nk.ID))
			blocks = buildBlock(blocks, BlockNextKey, data)
		}
	}
	for _, clove := range cloves {
		blocks = buildBlock(blocks, BlockGarlic, clove.EncodeRatchet())
	}
	if ackreq {
		blocks = buildBlock(blocks, BlockAckRequest, []byte{0})
	}
	if len(acks) > 0 {
		data := make([]byte, 4*len(acks))
		for i, a := range acks {
			binary.BigEndian.PutUint16(data[4*i:], uint16(a.TagSetID))
			binary.BigEndian.PutUint16(data[4*i+2:], uint16(a.N))
		}
		blocks = buildBlock(blocks, BlockAck, data)
	}

	// Padding. Reference: ECIESAEADEngine createPayload tail.
	totlen := len(blocks) + overhead
	padlen := paddingLength(totlen, overhead == NSOverhead)
	if padlen > 0 {
		blocks = buildBlock(blocks, BlockPadding, make([]byte, padlen))
	}
	return blocks
}

// Message overhead constants, used only for the padding calculation.
// Reference: ECIESAEADEngine NS_OVERHEAD/NSR_OVERHEAD/ES_OVERHEAD.
const (
	NSOverhead  = 96
	NSROverhead = 72
	ESOverhead  = 24
)

// paddingLength computes the padding block data length for a payload
// of totlen bytes (blocks + overhead). isNS enables the muxed-decrypt
// favor adjustment.
func paddingLength(totlen int, isNS bool) int {
	for _, b := range []int{padB1, padB2, padB3} {
		if totlen > b-BlockHeaderSize && totlen <= b {
			return 0 // no room for a padding block
		}
	}
	fixed := 0
	for _, b := range []int{padB1, padB2, padB3} {
		if totlen > b-BlockHeaderSize-maxPad && totlen <= b-BlockHeaderSize {
			fixed = b - BlockHeaderSize - totlen
			break
		}
	}
	if fixed > 0 {
		return fixed
	}
	n, err := rand.Int(rand.Reader, maxPadBig)
	if err != nil {
		return 0
	}
	padlen := int(n.Int64()) // [0, 16)
	if isNS && (totlen+BlockHeaderSize+padlen)&0x0f == 2 {
		// do a favor for muxed decrypt
		if padlen > 0 {
			padlen--
		} else {
			padlen++
		}
	}
	return padlen
}

var maxPadBig = big.NewInt(maxPad)

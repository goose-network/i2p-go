package ntcp2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// Payload block types. Reference: NTCP2Payload.java.
const (
	BlockDateTime    = 0
	BlockOptions     = 1
	BlockRouterInfo  = 2
	BlockI2NP        = 3
	BlockTermination = 4
	BlockPadding     = 254
)

// Termination reasons. Reference: NTCPConnection REASON_* constants.
const (
	TerminateUnspecified  = 0
	TerminateTermination  = 1
	TerminateTimeout      = 2
	TerminateAEAD         = 4
	TerminateOptions      = 5
	TerminateSigType      = 6
	TerminateSkew         = 7
	TerminatePadding      = 8
	TerminateFraming      = 9
	TerminatePayload      = 10
	TerminateMsg1         = 11
	TerminateMsg2         = 12
	TerminateMsg3         = 13
	TerminateFrameTimeout = 14
	TerminateSigFail      = 15
	TerminateSMismatch    = 16
	TerminateBanned       = 17
)

// maxRISize is the largest RouterInfo accepted in a block.
// Reference: RouterInfo.MAX_UNCOMPRESSED_SIZE.
const maxRISize = 64 * 1024

// Block is one NTCP2 payload block: type, and the data after the
// 3-byte header (type + 2-byte big-endian length).
type Block struct {
	Type int
	Data []byte
}

// Encode appends the block encoding (3-byte header + data) to buf.
// Reference: NTCP2Payload.Block.write.
func (b Block) Encode(buf []byte) []byte {
	buf = append(buf, byte(b.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b.Data)))
	return append(buf, b.Data...)
}

// EncodeBlocks serializes blocks into a payload. The padding block, if
// any, must be last.
func EncodeBlocks(blocks []Block) []byte {
	var n int
	for _, b := range blocks {
		n += 3 + len(b.Data)
	}
	buf := make([]byte, 0, n)
	for _, b := range blocks {
		buf = b.Encode(buf)
	}
	return buf
}

// Block constructors.

// DateTimeBlock returns a timestamp block (4-byte seconds).
// Reference: NTCP2Payload.DateTimeBlock.
func DateTimeBlock(t time.Time) Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32((t.UnixMilli()+500)/1000))
	return Block{Type: BlockDateTime, Data: data}
}

// I2NPBlock wraps a raw NTCP2-format I2NP message (9-byte header).
// Reference: NTCP2Payload.I2NPBlock.
func I2NPBlock(msg []byte) Block {
	return Block{Type: BlockI2NP, Data: msg}
}

// TerminationBlock builds the termination block.
// Reference: NTCP2Payload.TerminationBlock.
func TerminationBlock(reason int, lastReceived uint64) Block {
	d := make([]byte, 9)
	binary.BigEndian.PutUint64(d, lastReceived)
	d[8] = byte(reason)
	return Block{Type: BlockTermination, Data: d}
}

// PaddingBlock returns a zero padding block of n bytes.
// Reference: NTCP2Payload.PaddingBlock.
func PaddingBlock(n int) Block {
	return Block{Type: BlockPadding, Data: make([]byte, n)}
}

// ParsedBlocks is the result of decoding a payload: the blocks and the
// flags the transport layer needs.
type ParsedBlocks struct {
	Blocks []Block
	// DateTime is set when a DateTime block was present.
	DateTime time.Time
	// Termination is set when a termination block was present.
	Termination struct {
		Reason   int
		LastRecv uint64
	}
	// Flood is set when the (handshake) RouterInfo block requested
	// flooding.
	Flood bool
	// PaddingLen counts padding bytes (stats).
	PaddingLen int
}

// ParseBlocks decodes and validates a payload. In the NTCP2 handshake
// (message 3 part 2) the first block must be the RouterInfo; in the
// data phase any set is allowed. Padding must be last; only padding may
// follow a termination block. RouterInfo blocks are signature-verified
// (the Java reference passes verifySig=true in both phases).
// Reference: NTCP2Payload.processPayload.
func ParseBlocks(payload []byte, isHandshake bool) (*ParsedBlocks, error) {
	res := &ParsedBlocks{}
	i := 0
	gotPadding := false
	gotTermination := false
	blocks := 0
	for i < len(payload) {
		if gotPadding {
			return nil, fmt.Errorf("ntcp2: illegal block %d after padding", payload[i])
		}
		typ := int(payload[i])
		i++
		if i+2 > len(payload) {
			return nil, errors.New("ntcp2: truncated block header")
		}
		length := int(binary.BigEndian.Uint16(payload[i : i+2]))
		i += 2
		if i+length > len(payload) {
			return nil, fmt.Errorf("ntcp2: block type %d length %d runs over payload", typ, length)
		}
		blockData := payload[i : i+length]
		i += length
		if gotTermination && typ != BlockPadding {
			return nil, fmt.Errorf("ntcp2: illegal block %d after termination", typ)
		}
		if isHandshake && blocks == 0 && typ != BlockRouterInfo {
			return nil, fmt.Errorf("ntcp2: illegal first block %d in handshake", typ)
		}
		switch typ {
		case BlockDateTime:
			if isHandshake {
				return nil, errors.New("ntcp2: datetime block in handshake")
			}
			if length != 4 {
				return nil, fmt.Errorf("ntcp2: bad datetime length %d", length)
			}
			res.DateTime = time.UnixMilli(int64(binary.BigEndian.Uint32(blockData)) * 1000)
		case BlockOptions:
			// Opaque options; no validation.
		case BlockRouterInfo:
			if length < 1 {
				return nil, errors.New("ntcp2: empty RouterInfo block")
			}
			if length-1 > maxRISize {
				return nil, fmt.Errorf("ntcp2: RI too big: %d", length-1)
			}
			// Signature verification, as in RouterInfo.readBytes(..., true).
			if _, err := data.ReadRouterInfo(blockData[1:], true); err != nil {
				return nil, fmt.Errorf("ntcp2: bad RI block: %w", err)
			}
			res.Flood = blockData[0]&0x01 != 0 && length < 3*1024
		case BlockI2NP:
			if isHandshake {
				return nil, errors.New("ntcp2: I2NP block in handshake")
			}
			// Parsed by the i2np layer; the transport stays agnostic.
		case BlockTermination:
			if isHandshake {
				return nil, errors.New("ntcp2: termination block in handshake")
			}
			if length < 9 {
				return nil, fmt.Errorf("ntcp2: bad termination length %d", length)
			}
			res.Termination.Reason = int(blockData[8])
			res.Termination.LastRecv = binary.BigEndian.Uint64(blockData[:8])
			gotTermination = true
		case BlockPadding:
			gotPadding = true
			res.PaddingLen = length
		default:
			// Unknown blocks are skipped.
		}
		res.Blocks = append(res.Blocks, Block{Type: typ, Data: append([]byte(nil), blockData...)})
		blocks++
	}
	if isHandshake && blocks == 0 {
		return nil, errors.New("ntcp2: no blocks in handshake payload")
	}
	return res, nil
}

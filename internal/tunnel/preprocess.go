// Tunnel message preprocessing: fragmenting an I2NP message into
// 1024-byte preprocessed tunnel messages and parsing them back.
//
// A preprocessed tunnel message is:
//
//	[16B random IV]
//	[4B  = SHA256(fragments || IV)[0:4]]   (fragments = the
//	                                         {instructions, fragment}
//	                                         pairs region)
//	[nonzero random padding]
//	[0x00 terminator]
//	[{instructions, fragment} pairs]
//
// Fragment instruction encoding (first fragment / full message):
//
//	[control byte]
//	[4B next tunnel ID]        (TUNNEL mode)
//	[32B next router hash]     (TUNNEL or ROUTER mode)
//	[4B message ID]            (if fragmented)
//	[2B payload size]
//	[payload]
//
// control = 0 | MASK_TUNNEL(1<<5 if toTunnel) | MASK_ROUTER(2<<5 if
// toRouter only) | MASK_FRAGMENTED(1<<3 if fragmented).
//
// Subsequent fragment:
//
//	[control = 0x80 | (fragNum << 1) | isLast]
//	[4B message ID][2B payload size][payload]
//
// Reference: TrivialPreprocessor.java, FragmentHandler.java.
package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// PreprocessedSize is the fixed tunnel message size. Reference:
// TrivialPreprocessor.PREPROCESSED_SIZE.
const PreprocessedSize = 1024

// Control byte masks. Reference: TrivialPreprocessor.java.
const (
	maskIsSubsequent = 0x80
	maskType         = 0x60 // bits 5-6: delivery type
	maskFragmented   = 0x08
	maskExtended     = 0x04
	maskFragmentNum  = 0x7e
)

// Delivery types. Reference: TrivialPreprocessor.java
// (TYPE_LOCAL/TYPE_TUNNEL/TYPE_ROUTER).
const (
	typeLocal  = 0
	typeTunnel = 1
	typeRouter = 2
	typeUndef  = 3
)

// Fragment is one parsed {instructions, payload} pair.
type Fragment struct {
	Subsequent bool
	// First-fragment delivery mode and target.
	ToTunnel uint32
	ToRouter []byte // 32 bytes when mode is tunnel or router
	// Set on the first fragment when the message is fragmented; on
	// every subsequent fragment.
	MessageID  uint32
	Fragmented bool
	FragNum    int
	IsLast     bool
	Payload    []byte
}

// instructionsSize returns the encoded size of a first-fragment
// instruction header. Reference: TrivialPreprocessor.
// getInstructionsSize.
func instructionsSize(toTunnel bool, toRouter bool) int {
	n := 1
	if toTunnel {
		n += 4
	}
	if toRouter {
		n += 32
	}
	return n + 2
}

// PreprocessMessage fragments data (a complete I2NP message in the
// full 16-byte-header form) into one or more preprocessed tunnel
// messages, addressed per toRouter/toTunnel (both nil/0 = local
// delivery). Returns the 1024-byte blocks.
// Reference: TrivialPreprocessor.preprocess / writeFirstFragment /
// writeSubsequentFragment.
func PreprocessMessage(data []byte, messageID uint32, toRouter []byte, toTunnel uint32) ([][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("tunnel: empty message")
	}
	var blocks [][]byte
	fragNum := 0
	off := 0
	for off < len(data) || off == 0 && len(data) == 0 {
		var frags []byte
		var err error
		if fragNum == 0 {
			frags, off, err = writeFirstFragment(data, off, messageID, toRouter, toTunnel)
		} else {
			frags, off, err = writeSubsequentFragment(data, off, messageID, fragNum)
		}
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, wrapFragments(frags))
		fragNum++
	}
	return blocks, nil
}

// writeFirstFragment writes the first (possibly only) fragment of the
// message at the start of a fresh fragment region, returning the
// region and the new data offset.
// Reference: TrivialPreprocessor.writeFirstFragment.
func writeFirstFragment(data []byte, off int, messageID uint32, toRouter []byte, toTunnel uint32) ([]byte, int, error) {
	toTunnelSet := toTunnel != 0
	toRouterSet := toRouter != nil
	instrLen := instructionsSize(toTunnelSet, toRouterSet)
	payloadLen := len(data) - off
	fragmented := false
	// The threshold keeps room for the message ID that fragmentation
	// adds, plus the block overhead (IV + hash + terminator).
	if instrLen+payloadLen+IVSize+1+4+4 > PreprocessedSize {
		fragmented = true
		instrLen += 4
		payloadLen = PreprocessedSize - IVSize - 1 - 4 - instrLen
		if payloadLen <= 0 {
			return nil, off, fmt.Errorf("tunnel: fragment too small")
		}
	}

	buf := make([]byte, 0, instrLen+payloadLen)
	var control byte
	if toTunnelSet {
		control |= typeTunnel << 5
	} else if toRouterSet {
		control |= typeRouter << 5
	}
	if fragmented {
		control |= maskFragmented
	}
	buf = append(buf, control)
	if toTunnelSet {
		buf = binary.BigEndian.AppendUint32(buf, toTunnel)
	}
	if toRouterSet {
		buf = append(buf, toRouter...)
	}
	if fragmented {
		buf = binary.BigEndian.AppendUint32(buf, messageID)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(payloadLen))
	buf = append(buf, data[off:off+payloadLen]...)
	return buf, off + payloadLen, nil
}

// writeSubsequentFragment writes a continuation fragment.
// Reference: TrivialPreprocessor.writeSubsequentFragment.
func writeSubsequentFragment(data []byte, off int, messageID uint32, fragNum int) ([]byte, int, error) {
	payloadLen := len(data) - off
	isLast := true
	if payloadLen+7+IVSize+1+4 > PreprocessedSize {
		isLast = false
		payloadLen = PreprocessedSize - IVSize - 1 - 4 - 7
	}
	control := byte(maskIsSubsequent | (fragNum << 1))
	if isLast {
		control |= 1
	}
	buf := make([]byte, 0, 7+payloadLen)
	buf = append(buf, control)
	buf = binary.BigEndian.AppendUint32(buf, messageID)
	buf = binary.BigEndian.AppendUint16(buf, uint16(payloadLen))
	buf = append(buf, data[off:off+payloadLen]...)
	return buf, off + payloadLen, nil
}

// wrapFragments turns a fragment region into a full preprocessed
// tunnel message: IV + hash + nonzero padding + 0x00 + fragments.
// Reference: TrivialPreprocessor.preprocess.
func wrapFragments(frags []byte) []byte {
	block := make([]byte, PreprocessedSize)
	iv := make([]byte, IVSize)
	rand.Read(iv)

	// h = SHA256(fragments || IV)[0:4]
	h := sha256.New()
	h.Write(frags)
	h.Write(iv)
	sum := h.Sum(nil)

	copy(block[0:IVSize], iv)
	copy(block[IVSize:IVSize+4], sum[:4])
	// Nonzero random padding up to the fragment region.
	padEnd := PreprocessedSize - len(frags) - 1
	for i := IVSize + 4; i < padEnd; i++ {
		block[i] = 0x01
	}
	// Randomize the padding (nonzero).
	pad := make([]byte, padEnd-IVSize-4)
	rand.Read(pad)
	for i, b := range pad {
		if b == 0 {
			b = 0x01
		}
		block[IVSize+4+i] = b
	}
	block[padEnd] = 0x00
	copy(block[padEnd+1:], frags)
	return block
}

// VerifyAndParse verifies a preprocessed tunnel message and returns
// its fragments. Reference: FragmentHandler.verifyPreprocessed +
// receiveTunnelMessage.
func VerifyAndParse(block []byte) ([]*Fragment, error) {
	if len(block) != PreprocessedSize {
		return nil, fmt.Errorf("tunnel: block size %d", len(block))
	}
	// Find the padding terminator.
	padEnd := IVSize + 4
	for block[padEnd] != 0x00 {
		padEnd++
		if padEnd >= len(block) {
			return nil, fmt.Errorf("tunnel: padding-only message")
		}
	}
	padEnd++ // skip the 0x00

	// Verify: SHA256(fragments || IV)[0:4] == block[16:20].
	h := sha256.New()
	h.Write(block[padEnd:])
	h.Write(block[:IVSize])
	sum := h.Sum(nil)
	for i := 0; i < 4; i++ {
		if sum[i] != block[IVSize+i] {
			return nil, fmt.Errorf("tunnel: hash verify fail")
		}
	}

	var frags []*Fragment
	off := padEnd
	for off < len(block) {
		f, n, err := parseFragment(block, off)
		if err != nil {
			return nil, err
		}
		frags = append(frags, f)
		off = n
	}
	return frags, nil
}

// parseFragment decodes one {instructions, payload} pair at off.
// Returns the fragment and the offset after it.
// Reference: FragmentHandler.receiveFragment.
func parseFragment(block []byte, off int) (*Fragment, int, error) {
	if off >= len(block) {
		return nil, off, fmt.Errorf("tunnel: fragment at %d", off)
	}
	control := block[off]
	f := &Fragment{Subsequent: control&maskIsSubsequent != 0}
	off++
	if f.Subsequent {
		f.FragNum = int(control&maskFragmentNum) >> 1
		f.IsLast = control&1 != 0
		if off+6 > len(block) {
			return nil, off, fmt.Errorf("tunnel: short subsequent fragment")
		}
		f.MessageID = binary.BigEndian.Uint32(block[off : off+4])
		size := int(binary.BigEndian.Uint16(block[off+4 : off+6]))
		off += 6
		if off+size > len(block) {
			return nil, off, fmt.Errorf("tunnel: fragment payload overruns block")
		}
		f.Payload = block[off : off+size]
		return f, off + size, nil
	}

	dtype := int(control&maskType) >> 5
	if control&maskExtended != 0 || control&0x01 != 0 && false {
		return nil, off, fmt.Errorf("tunnel: extended instructions unsupported")
	}
	if dtype == typeUndef {
		return nil, off, fmt.Errorf("tunnel: undefined delivery type")
	}
	if dtype == typeTunnel {
		if off+4 > len(block) {
			return nil, off, fmt.Errorf("tunnel: short tunnel instruction")
		}
		f.ToTunnel = binary.BigEndian.Uint32(block[off : off+4])
		off += 4
	}
	if dtype == typeTunnel || dtype == typeRouter {
		if off+32 > len(block) {
			return nil, off, fmt.Errorf("tunnel: short router instruction")
		}
		f.ToRouter = block[off : off+32]
		off += 32
	}
	f.Fragmented = control&maskFragmented != 0
	if f.Fragmented {
		if off+4 > len(block) {
			return nil, off, fmt.Errorf("tunnel: short fragment id")
		}
		f.MessageID = binary.BigEndian.Uint32(block[off : off+4])
		off += 4
	}
	if off+2 > len(block) {
		return nil, off, fmt.Errorf("tunnel: short size")
	}
	size := int(binary.BigEndian.Uint16(block[off : off+2]))
	off += 2
	if off+size > len(block) {
		return nil, off, fmt.Errorf("tunnel: fragment payload overruns block")
	}
	f.Payload = block[off : off+size]
	return f, off + size, nil
}

package ntcp2

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
)

// BufferSize is the payload capacity of one frame.
// Reference: NTCPConnection.BUFFER_SIZE.
const BufferSize = 16 * 1024

// MaxMsgSize is the largest message we accept in a frame.
// Reference: NTCPConnection.NTCP2_MAX_MSG_SIZE.
const MaxMsgSize = 65516

// sipState is one direction's SipHash length-obfuscation state: two
// 64-bit keys and the 8-byte ratchet IV. Reference: NTCPConnection
// (_sendSipk1/_sendSipk2/_sendSipIV and the NTCP2ReadState mirror).
type sipState struct {
	k0, k1 uint64
	iv     [8]byte
}

func newSipState(key []byte) *sipState {
	s := &sipState{
		k0: binary.LittleEndian.Uint64(key[0:8]),
		k1: binary.LittleEndian.Uint64(key[8:16]),
	}
	copy(s.iv[:], key[16:24])
	return s
}

// xorLength returns the two length bytes, XORed with the current
// SipHash ratchet output, and advances the ratchet.
// Reference: NTCPConnection.sendNTCP2 (send side) and
// NTCP2ReadState.receive (receive side).
func (s *sipState) xorLength(frameLen int) (b0, b1 byte) {
	sipIV := i2pcrypto.SipHash24(s.k0, s.k1, s.iv[:])
	binary.LittleEndian.PutUint64(s.iv[:], sipIV)
	return byte(frameLen>>8) ^ byte(sipIV>>8), byte(frameLen) ^ byte(sipIV)
}

// unxorLength inverts xorLength (SipHash is symmetric here: both sides
// ratchet the same way).
func (s *sipState) unxorLength(e0, e1 byte) int {
	sipIV := i2pcrypto.SipHash24(s.k0, s.k1, s.iv[:])
	binary.LittleEndian.PutUint64(s.iv[:], sipIV)
	b0 := e0 ^ byte(sipIV>>8)
	b1 := e1 ^ byte(sipIV)
	return int(b0)<<8 | int(b1)
}

// writeFrame encrypts and writes one data-phase frame: the
// SipHash-obfuscated 2-byte length, the AEAD ciphertext, and the tag.
// AD is nil. Reference: NTCPConnection.sendNTCP2.
func (c *Conn) writeFrame(payload []byte) error {
	if len(payload)+macSize > MaxMsgSize+macSize {
		return fmt.Errorf("ntcp2: frame payload too large %d", len(payload))
	}
	frameLen := len(payload) + macSize
	out := make([]byte, 2+frameLen)
	copy(out[2:], c.send.Seal(nil, payload))
	c.sendSip.xorLengthTo(out[0:2], frameLen)
	_, err := c.conn.Write(out)
	return err
}

// xorLengthTo writes the obfuscated length into dst[0:2].
func (s *sipState) xorLengthTo(dst []byte, frameLen int) {
	dst[0], dst[1] = s.xorLength(frameLen)
}

// readFrame reads and decrypts one data-phase frame, returning the
// plaintext payload. Reference: NTCP2ReadState.receive +
// decryptAndProcess.
func (c *Conn) readFrame() ([]byte, error) {
	var lenBytes [2]byte
	if _, err := io.ReadFull(c.reader, lenBytes[:]); err != nil {
		return nil, err
	}
	frameLen := c.recvSip.unxorLength(lenBytes[0], lenBytes[1])
	if frameLen < macSize {
		return nil, fmt.Errorf("ntcp2: short frame length %d", frameLen)
	}
	if frameLen > MaxMsgSize+macSize {
		return nil, fmt.Errorf("ntcp2: frame length %d too large", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.reader, frame); err != nil {
		return nil, err
	}
	payload, err := c.recv.Open(nil, frame)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// The per-direction AEAD nonce counters live inside the i2pcrypto.AEAD
// instances returned by Split() and are advanced by Seal/Open, so no
// separate bookkeeping is needed here.

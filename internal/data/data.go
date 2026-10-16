// Package data implements the I2P common data structure formats: the
// big-endian primitive encodings from DataHelper, the I2P base32/base64
// alphabets, and small shared data structures.
//
// This package mirrors the Java reference implementation files
// core/java/src/net/i2p/data/DataHelper.java, Base64.java, and Base32.java
// in the I2P reference router (../i2p.i2p).
package data

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"time"
)

// DATE_LENGTH is the number of bytes in an I2P date (ms since Unix epoch).
// Reference: DataHelper.java DATE_LENGTH.
const DATE_LENGTH = 8

// AppendLong returns the numBytes-long big-endian encoding of value.
// Reference: DataHelper.toLong / writeLong.
func AppendLong(numBytes int, value uint64) []byte {
	out := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		shift := uint((numBytes - 1 - i) * 8)
		out[i] = byte(value >> shift)
	}
	return out
}

// ReadLong reads a numBytes-long big-endian unsigned integer at off.
// Reference: DataHelper.readLong / fromLong.
func ReadLong(b []byte, off, numBytes int) (uint64, error) {
	if off < 0 || numBytes < 0 || off+numBytes > len(b) {
		return 0, fmt.Errorf("read long off=%d n=%d len=%d", off, numBytes, len(b))
	}
	var v uint64
	for i := 0; i < numBytes; i++ {
		v = v<<8 | uint64(b[off+i])
	}
	return v, nil
}

// AppendDate appends an I2P date (8-byte ms since epoch; 0 = null date).
// Reference: DataHelper.writeDate.
func AppendDate(d time.Time) []byte {
	if d.IsZero() {
		return AppendLong(DATE_LENGTH, 0)
	}
	return AppendLong(DATE_LENGTH, uint64(d.UnixMilli()))
}

// ReadDate reads an I2P date at off. The null date is returned as zero time.
// Reference: DataHelper.readDate.
func ReadDate(b []byte, off int) (time.Time, error) {
	v, err := ReadLong(b, off, DATE_LENGTH)
	if err != nil {
		return time.Time{}, err
	}
	if v == 0 {
		return time.Time{}, nil
	}
	return time.UnixMilli(int64(v)), nil
}

// i2pB64Alphabet is the I2P base64 alphabet: standard base64 with
// '+' → '-' and '/' → '~'. Reference: Base64.java ALPHABET_I2P.
const i2pB64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

// EncodeToI2PBase64 encodes bytes using the I2P URL-safe base64 alphabet
// (no padding).
func EncodeToI2PBase64(b []byte) string {
	return encodeB64(b, i2pB64Alphabet)
}

// DecodeI2PBase64 decodes I2P base64 (also accepts the standard alphabet,
// and ignores whitespace). Reference: Base64.safeDecode.
func DecodeI2PBase64(s string) ([]byte, error) {
	var out []byte
	var acc uint32
	var nbits uint
	for _, c := range s {
		var v byte
		switch {
		case c >= 'A' && c <= 'Z':
			v = byte(c - 'A')
		case c >= 'a' && c <= 'z':
			v = byte(c-'a') + 26
		case c >= '0' && c <= '9':
			v = byte(c-'0') + 52
		case c == '-' || c == '+':
			v = 62
		case c == '~' || c == '/':
			v = 63
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
			continue
		case c == '=':
			continue
		default:
			return nil, fmt.Errorf("invalid base64 character %q", c)
		}
		acc = acc<<6 | uint32(v)
		nbits += 6
		if nbits >= 8 {
			nbits -= 8
			out = append(out, byte(acc>>nbits))
		}
	}
	return out, nil
}

func encodeB64(b []byte, alphabet string) string {
	var out []byte
	var acc, nbits uint32
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		nbits += 8
		for nbits >= 6 {
			nbits -= 6
			out = append(out, alphabet[(acc>>nbits)&0x3f])
		}
	}
	if nbits > 0 {
		out = append(out, alphabet[(acc<<(6-nbits))&0x3f])
	}
	return string(out)
}

// i2pB32Encoding is lowercase RFC 4648 base32 without padding.
// Reference: Base32.java.
var i2pB32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// EncodeToI2PBase32 encodes bytes as lowercase unpadded base32.
func EncodeToI2PBase32(b []byte) string {
	return i2pB32Encoding.EncodeToString(b)
}

// DecodeI2PBase32 decodes lowercase unpadded base32 (as used in .b32.i2p).
func DecodeI2PBase32(s string) ([]byte, error) {
	return i2pB32Encoding.DecodeString(s)
}

// stdB64Raw is standard base64 without padding (used for NTCP2 address
// options and similar inside-protocol base64, which is NOT the I2P alphabet).
var stdB64Raw = base64.RawStdEncoding

// StdBase64Encode encodes using standard base64 without padding.
func StdBase64Encode(b []byte) string { return stdB64Raw.EncodeToString(b) }

// StdBase64Decode decodes standard unpadded base64.
func StdBase64Decode(s string) ([]byte, error) { return stdB64Raw.DecodeString(s) }

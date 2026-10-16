// Package i2pcrypto implements the cryptographic primitives I2P uses
// in its transport and garlic layers: the 8-byte-nonce ChaCha20-Poly1305
// AEAD, the I2P HKDF flavor, and SipHash-2-4.
//
// This package mirrors the Java reference implementation files
// router/java/src/com/southernstorm/noise/protocol/ChaChaPolyCipherState.java,
// core/java/src/net/i2p/crypto/HKDF.java, and
// core/java/src/net/i2p/crypto/SipHashInline.java in the I2P reference
// router (../i2p.i2p).
package i2pcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/chacha20"
)

// ErrBadTag is returned when AEAD authentication fails.
var ErrBadTag = errors.New("i2pcrypto: message authentication failed")

// AEAD is the I2P ChaCha20-Poly1305 cipher state: a key and a 64-bit
// message counter ("nonce") that starts at zero and increments per
// message. ChaCha is run with an 8-byte nonce layout: the block counter
// in state words 12/13 (starting at 0; block 0 keys Poly1305 and
// encryption starts at block 1) and the message counter in words 14/15.
// Reference: ChaChaPolyCipherState (setup/encrypt/finish).
type AEAD struct {
	key [32]byte
	n   uint64
}

// NewAEAD returns an AEAD keyed with key and the counter at zero.
func NewAEAD(key []byte) *AEAD {
	a := &AEAD{}
	copy(a.key[:], key)
	return a
}

// SetNonce sets the message counter.
func (a *AEAD) SetNonce(n uint64) { a.n = n }

// Nonce returns the message counter.
func (a *AEAD) Nonce() uint64 { return a.n }

// i2pNonce maps I2P's 8-byte-nonce state layout onto the RFC 7539
// 12-byte nonce of x/crypto/chacha20: word 13 = counter high (always 0),
// word 14 = nonce low, word 15 = nonce high. Reference: ChaChaCore.initIV.
func i2pNonce(n uint64) []byte {
	nonce := make([]byte, chacha20.NonceSize)
	binary.LittleEndian.PutUint32(nonce[4:8], uint32(n))
	binary.LittleEndian.PutUint32(nonce[8:12], uint32(n>>32))
	return nonce
}

// Seal encrypts and authenticates plaintext, appending the 16-byte tag.
// The MAC covers pad16(ad) || pad16(ct) || LE64(len(ad)) || LE64(len(ct)).
// Reference: ChaChaPolyCipherState.encryptWithAd.
func (a *AEAD) Seal(ad, plaintext []byte) []byte {
	out := a.seal(i2pNonce(a.n), ad, plaintext)
	a.n++
	return out
}

// seal is the Seal core with an explicit 12-byte ChaCha nonce, so tests
// can run the RFC 7539 AEAD vector (whose word 13 is nonzero).
func (a *AEAD) seal(nonce []byte, ad, plaintext []byte) []byte {
	pk := a.polyKeyBlockWithNonce(nonce)
	c, err := chacha20.NewUnauthenticatedCipher(a.key[:], nonce)
	if err != nil {
		panic("i2pcrypto: bad key/nonce: " + err.Error())
	}
	c.SetCounter(1)
	ct := make([]byte, len(plaintext))
	c.XORKeyStream(ct, plaintext)
	var tag [16]byte
	poly1305Sum(&tag, a.macInput(ad, ct), &pk)
	return append(ct, tag[:]...)
}

// Open verifies and decrypts a Seal output. Returns ErrBadTag on
// failure. Reference: ChaChaPolyCipherState.decryptWithAd.
func (a *AEAD) Open(ad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrBadTag
	}
	ct, tag := ciphertext[:len(ciphertext)-16], ciphertext[len(ciphertext)-16:]
	pk := a.polyKeyBlock()
	var expected [16]byte
	poly1305Sum(&expected, a.macInput(ad, ct), &pk)
	var diff byte
	for i := 0; i < 16; i++ {
		diff |= expected[i] ^ tag[i]
	}
	if diff != 0 {
		return nil, ErrBadTag
	}
	c, err := chacha20.NewUnauthenticatedCipher(a.key[:], i2pNonce(a.n))
	if err != nil {
		panic("i2pcrypto: bad key/nonce: " + err.Error())
	}
	c.SetCounter(1)
	pt := make([]byte, len(ct))
	c.XORKeyStream(pt, ct)
	a.n++
	return pt, nil
}

// polyKeyBlock returns the first 32 bytes of the block-0 keystream.
func (a *AEAD) polyKeyBlock() [32]byte { return a.polyKeyBlockWithNonce(i2pNonce(a.n)) }

func (a *AEAD) polyKeyBlockWithNonce(nonce []byte) [32]byte {
	c, err := chacha20.NewUnauthenticatedCipher(a.key[:], nonce)
	if err != nil {
		panic("i2pcrypto: bad key/nonce: " + err.Error())
	}
	var out [32]byte
	var zero [32]byte
	c.XORKeyStream(out[:], zero[:])
	return out
}

// macInput builds pad16(ad) || pad16(ct) || LE64(len(ad)) || LE64(len(ct)).
// Java's Poly1305.pad() is a no-op when already aligned, and an empty
// AD contributes no bytes at all (setup only calls update/pad for
// non-null ad).
func (a *AEAD) macInput(ad, ct []byte) []byte {
	pad := func(b []byte) []byte {
		if len(b)%16 == 0 {
			return b
		}
		p := make([]byte, len(b)+(16-len(b)%16))
		copy(p, b)
		return p
	}
	var tail [16]byte
	binary.LittleEndian.PutUint64(tail[0:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(tail[8:16], uint64(len(ct)))
	out := make([]byte, 0, len(ad)+len(ct)+32)
	out = append(out, pad(ad)...)
	out = append(out, pad(ct)...)
	return append(out, tail[:]...)
}

// poly1305Sum computes the RFC 8439 Poly1305 tag of msg under key.
//
// 3x64-bit limb implementation (the structure poly1305-donna-64 and the
// Go standard library use): the accumulator h is held as three
// saturated little-endian limbs h[0] + h[1]<<64 + h[2]<<128, multiplied
// by the clamped 2-limb r and partially reduced with the identity
// 2^130 ≡ 5 (mod 2^130-5).
func poly1305Sum(tag *[16]byte, msg []byte, key *[32]byte) {
	// Clamp r and load s.
	r0 := binary.LittleEndian.Uint64(key[0:8]) & 0x0FFFFFFC0FFFFFFF
	r1 := binary.LittleEndian.Uint64(key[8:16]) & 0x0FFFFFFC0FFFFFFC
	s0 := binary.LittleEndian.Uint64(key[16:24])
	s1 := binary.LittleEndian.Uint64(key[24:32])

	var h0, h1, h2 uint64
	for len(msg) > 0 {
		// h += m, with the length bit set just past the message chunk.
		var m0, m1 uint64
		if len(msg) >= 16 {
			m0 = binary.LittleEndian.Uint64(msg[0:8])
			m1 = binary.LittleEndian.Uint64(msg[8:16])
			msg = msg[16:]
			h2++ // bit 128
		} else {
			var buf [16]byte
			copy(buf[:], msg)
			buf[len(msg)] = 1
			m0 = binary.LittleEndian.Uint64(buf[0:8])
			m1 = binary.LittleEndian.Uint64(buf[8:16])
			msg = nil
		}
		var c uint64
		h0, c = bits.Add64(h0, m0, 0)
		h1, c = bits.Add64(h1, m1, c)
		h2 += c

		// h *= r: five 128-bit products (h2's products fit in 64 bits).
		h0r0hi, h0r0lo := bits.Mul64(h0, r0)
		h1r0hi, h1r0lo := bits.Mul64(h1, r0)
		h2r0 := h2 * r0
		h0r1hi, h0r1lo := bits.Mul64(h0, r1)
		h1r1hi, h1r1lo := bits.Mul64(h1, r1)
		h2r1 := h2 * r1

		// Sum the overlapping columns into limbs t0..t3.
		t0 := h0r0lo
		t1, c := bits.Add64(h1r0lo, h0r1lo, 0)
		t2, c := bits.Add64(h2r0, h1r1lo, c)
		t3, _ := bits.Add64(h2r1, 0, c)
		t1, c = bits.Add64(t1, h0r0hi, 0)
		t2, c = bits.Add64(t2, h1r0hi, c)
		t3, _ = bits.Add64(t3, h1r1hi, c)
		t2, c = bits.Add64(t2, h0r1hi, c)
		t3, _ = bits.Add64(t3, 0, c)

		// Partial reduction mod 2^130-5: fold everything above bit 130
		// back in. cc = the portion of t2:t3 above the low 2 bits of t2,
		// shifted left by 2 relative to the fold identity, so adding cc
		// contributes 4c and cc>>2 contributes c.
		cc0, cc1 := t2&^3, t3
		h0, h1, h2 = t0, t1, t2&3
		h0, c = bits.Add64(h0, cc0, 0)
		h1, c = bits.Add64(h1, cc1, c)
		h2 += c
		cc0 = cc0>>2 | (cc1&3)<<62
		cc1 >>= 2
		h0, c = bits.Add64(h0, cc0, 0)
		h1, c = bits.Add64(h1, cc1, c)
		h2 += c
	}

	// Fully reduce: t = h - (2^130 - 5); keep t unless it underflowed.
	const p0 = 0xFFFFFFFFFFFFFFFB
	t0, b := bits.Sub64(h0, p0, 0)
	t1, b := bits.Sub64(h1, ^uint64(0), b)
	_, b = bits.Sub64(h2, 3, b)
	if b == 0 {
		h0, h1 = t0, t1
	}

	// tag = h + s mod 2^128.
	h0, c := bits.Add64(h0, s0, 0)
	h1, _ = bits.Add64(h1, s1, c)
	binary.LittleEndian.PutUint64(tag[0:8], h0)
	binary.LittleEndian.PutUint64(tag[8:16], h1)
}

// HKDF is the single-output I2P HKDF: PRK = HMAC-SHA256(salt=key,
// IKM=data), then out = HMAC(PRK, info||0x01). Reference: HKDF.java.
func HKDF(key, data []byte, info string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte(info))
	mac.Write([]byte{1})
	return mac.Sum(nil)
}

// HKDF2 is the two-output I2P HKDF: out1 = HMAC(PRK, info||0x01),
// out2 = HMAC(PRK, out1||info||0x02). Reference: HKDF.java (two-output
// calculate), and SymmetricState.hkdf.
func HKDF2(key, data []byte, info string) (out1, out2 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte(info))
	mac.Write([]byte{1})
	out1 = mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write(out1)
	mac.Write([]byte(info))
	mac.Write([]byte{2})
	out2 = mac.Sum(nil)
	return
}

// SipHash24 computes SipHash-2-4 with a 64-bit key.
// Reference: SipHashInline.hash24.
func SipHash24(k0, k1 uint64, data []byte) uint64 {
	v0 := 0x736f6d6570736575 ^ k0
	v1 := 0x646f72616e646f6d ^ k1
	v2 := 0x6c7967656e657261 ^ k0
	v3 := 0x7465646279746573 ^ k1
	round := func() {
		v0 += v1
		v2 += v3
		v1 = bits.RotateLeft64(v1, 13)
		v3 = bits.RotateLeft64(v3, 16)
		v1 ^= v0
		v3 ^= v2
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v1
		v0 += v3
		v1 = bits.RotateLeft64(v1, 17)
		v3 = bits.RotateLeft64(v3, 21)
		v1 ^= v2
		v3 ^= v0
		v2 = bits.RotateLeft64(v2, 32)
	}
	total := len(data)
	b := uint64(0)
	for len(data) >= 8 {
		m := binary.LittleEndian.Uint64(data)
		v3 ^= m
		round()
		round()
		v0 ^= m
		data = data[8:]
	}
	for i := len(data) - 1; i >= 0; i-- {
		b = b<<8 | uint64(data[i])
	}
	b |= uint64(total) << 56
	v3 ^= b
	round()
	round()
	v0 ^= b
	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}

package i2pcrypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// poly1305 vectors (edge cases: carries, reduction, 2^130-5 multiples).
// Source: the public Poly1305 test vectors used by the Go project's
// poly1305 package.
var poly1305Vectors = []struct{ key, in, tag string }{
	{
		key: "3b3a29e93b213a5c5c3b3b053a3a8c0d00000000000000000000000000000000",
		in:  "81d8b2e46a25213b58fee4213a2a28e921c12a9632516d3b73272727becf2129",
		tag: "6dc18b8c344cd79927118bbe84b7f314",
	},
	{
		key: "0100000000000000000000000000000000000000000000000000000000000000",
		in: "ffffffffffffffffffffffffffffffff" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		tag: "04000000000000000000000000000000", // (2^130-1) mod (2^130-5)
	},
	{
		key: "0100000000000000000000000000000000000000000000000000000000000000",
		in: "faffffffffffffffffffffffffffffff" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		tag: "faffffffffffffffffffffffffffffff", // (2^130-6) mod (2^130-5)
	},
	{
		key: "0100000000000000000000000000000000000000000000000000000000000000",
		in: "fbffffffffffffffffffffffffffffff" +
			"00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		tag: "00000000000000000000000000000000", // (2^130-5) mod (2^130-5)
	},
	{
		key: "0100000000000000000000000000000000000000000000000000000000000000",
		in: "faffffffffffffffffffffffffffffff" +
			"faffffffffffffffffffffffffffffff" +
			"00000000000000000000000000000000",
		tag: "f9ffffffffffffffffffffffffffffff", // (2*(2^130-6)) mod (2^130-5)
	},
}

func TestPoly1305(t *testing.T) {
	for i, v := range poly1305Vectors {
		var key [32]byte
		var tag [16]byte
		k, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatal(err)
		}
		in, err := hex.DecodeString(v.in)
		if err != nil {
			t.Fatal(err)
		}
		copy(key[:], k)
		poly1305Sum(&tag, in, &key)
		if got := hex.EncodeToString(tag[:]); got != v.tag {
			t.Errorf("vector %d: got %s want %s", i, got, v.tag)
		}
	}
}

// TestSipHash24Vectors runs the reference SipHash-2-4 test vectors
// (ported from siphash24.c, as in SipHashInlineTest.java).
func TestSipHash24Vectors(t *testing.T) {
	expected := []uint64{
		0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a,
		0x85676696d7fb7e2d, 0xcf2794e0277187b7, 0x18765564cd99a68d,
		0xcbc9466e58fee3ce, 0xab0200f58b01d137, 0x93f5f5799a932462,
		0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
		0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee,
		0xa129ca6149be45e5, 0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794,
		0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd, 0xbed65cf21aa2ee98,
		0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
		0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3,
	}
	k0, k1 := uint64(0x0706050403020100), uint64(0x0f0e0d0c0b0a0908)
	for i, want := range expected {
		msg := make([]byte, i)
		for j := range msg {
			msg[j] = byte(j)
		}
		if got := SipHash24(k0, k1, msg); got != want {
			t.Errorf("len %d: got %016x want %016x", i, got, want)
		}
	}
}

// TestAEADRoundTrip seals and opens messages of varying lengths with and
// without associated data, and checks tamper detection.
func TestAEADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	a := NewAEAD(key)
	plaintexts := [][]byte{
		nil,
		[]byte("a"),
		bytes.Repeat([]byte{7}, 63),
		bytes.Repeat([]byte{7}, 64),
		bytes.Repeat([]byte{9}, 1000),
	}
	ads := [][]byte{nil, []byte("ad"), bytes.Repeat([]byte{1}, 32)}
	for _, ad := range ads {
		for _, pt := range plaintexts {
			a.SetNonce(0)
			ct := a.Seal(ad, pt)
			a.SetNonce(0)
			got, err := a.Open(ad, ct)
			if err != nil {
				t.Fatalf("open failed (len=%d ad=%d): %v", len(pt), len(ad), err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch (len=%d)", len(pt))
			}
			if len(ct) != len(pt)+16 {
				t.Fatalf("bad ct length %d for pt %d", len(ct), len(pt))
			}
		}
	}
	// Tamper detection.
	a.SetNonce(0)
	ct := a.Seal(nil, []byte("hello world"))
	a.SetNonce(0)
	ct[0] ^= 1
	if _, err := a.Open(nil, ct); err != ErrBadTag {
		t.Fatalf("tampered ct: got %v, want ErrBadTag", err)
	}
	a.SetNonce(0)
	ct = a.Seal(nil, []byte("hello world"))
	a.SetNonce(0)
	ct[len(ct)-1] ^= 1
	if _, err := a.Open(nil, ct); err != ErrBadTag {
		t.Fatalf("tampered tag: got %v, want ErrBadTag", err)
	}
	// Wrong AD must fail.
	a.SetNonce(0)
	ct = a.Seal([]byte("ad1"), []byte("hello world"))
	a.SetNonce(0)
	if _, err := a.Open([]byte("ad2"), ct); err != ErrBadTag {
		t.Fatalf("wrong ad: got %v, want ErrBadTag", err)
	}
	// Nonce advance.
	a.SetNonce(0)
	c1 := a.Seal(nil, []byte("one"))
	c2 := a.Seal(nil, []byte("one"))
	if bytes.Equal(c1, c2) {
		t.Fatal("nonce did not advance")
	}
	if a.Nonce() != 2 {
		t.Fatalf("nonce = %d, want 2", a.Nonce())
	}
}

// TestAEADRFCVector runs the RFC 7539 AEAD vector as adapted by i2pd and
// the Java ChaChaPolyCipherState main() test: key 80..9f, nonce
// 0x4746454443424140 (message counter), the sunscreen plaintext, and
// the 12-byte AD. This is an end-to-end check of the 8-byte-nonce
// layout, block-0 keying, counter-from-1, and MAC framing.
func TestAEADRFCVector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 0x80)
	}
	ad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantCt, _ := hex.DecodeString(
		"d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116")
	wantTag, _ := hex.DecodeString("1ae10b594f09e26a7e902ecbd0600691")

	a := NewAEAD(key)
	// i2pd's vector adaptation: the RFC nonce 0x07,0,0,0 || 0x40..0x47
	// must be split across words 13-15 of the ChaCha state (the Java
	// test comments the word-13 assignment out, so it cannot reproduce
	// the vector; we run the true RFC construction through seal()).
	nonce := make([]byte, 12)
	nonce[0] = 0x07
	binary.LittleEndian.PutUint64(nonce[4:12], 0x4746454443424140)
	out := a.seal(nonce, ad, pt)
	if !bytes.Equal(out[:len(pt)], wantCt) {
		t.Fatalf("ciphertext mismatch\n got %x\nwant %x", out[:len(pt)], wantCt)
	}
	if !bytes.Equal(out[len(pt):], wantTag) {
		t.Fatalf("tag mismatch\n got %x\nwant %x", out[len(pt):], wantTag)
	}
	if a.Nonce() != 0 {
		t.Fatal("seal must not advance the message counter")
	}
}

// TestHKDF checks the I2P HKDF flavor.
func TestHKDF(t *testing.T) {
	out1, out2 := HKDF2([]byte("salt"), []byte("ikm"), "")
	if len(out1) != 32 || len(out2) != 32 {
		t.Fatalf("bad lengths %d %d", len(out1), len(out2))
	}
	if bytes.Equal(out1, out2) {
		t.Fatal("outputs identical")
	}
	o1a, o1b := HKDF2([]byte("salt"), []byte("ikm"), "")
	if !bytes.Equal(out1, o1a) || !bytes.Equal(out2, o1b) {
		t.Fatal("not deterministic")
	}
	single := HKDF([]byte("salt"), []byte("ikm"), "")
	if !bytes.Equal(single, out1) {
		t.Fatal("single-output disagrees with two-output first")
	}
}

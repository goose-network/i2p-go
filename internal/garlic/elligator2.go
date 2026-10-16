// Elligator2 encoding for X25519 public keys, used to make ECIES-Ratchet
// New Session messages indistinguishable from random data.
//
// This file ports the Java reference implementation
// router/java/src/net/i2p/router/crypto/ratchet/Elligator2.java in the
// I2P reference router (../i2p.i2p), which is itself ported from the
// Jan. 13, 2016 C version of https://github.com/Kleshni/Elligator-2.
package garlic

import (
	"crypto/rand"
	"math/big"
)

// Elligator2 curve constants: p = 2^255 - 19, A = 486662, u = 2.
// Reference: Elligator2.java static initializer.
var (
	elgP               = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	elgA               = big.NewInt(486662)
	elgNegA            = new(big.Int).Sub(elgP, elgA)
	elgU               = big.NewInt(2)
	elgInvU            = new(big.Int).ModInverse(elgU, elgP)
	elgDivPlusP3Over8  = new(big.Int).Div(new(big.Int).Add(elgP, big.NewInt(3)), big.NewInt(8))
	elgDivMinusP1Over2 = new(big.Int).Div(new(big.Int).Sub(elgP, big.NewInt(1)), big.NewInt(2))
	elgDivMinusP1Over4 = new(big.Int).Div(elgDivMinusP1Over2, big.NewInt(2))
	elgSqrtNegOne      = new(big.Int).Exp(big.NewInt(2), elgDivMinusP1Over4, elgP)
)

// legendre returns the Legendre symbol of a mod p (-1, 0, or 1).
// a^((p-1)/2) is either 1 (residue) or p-1 (non-residue).
// Reference: Elligator2.java legendre.
func legendre(a *big.Int) int {
	if a.Sign() == 0 {
		return 0
	}
	mp := new(big.Int).Exp(a, elgDivMinusP1Over2, elgP)
	if mp.Cmp(big.NewInt(1)) == 0 {
		return 1
	}
	return -1
}

// elgSquareRoot returns a square root of x mod p chosen canonically
// (result <= (p-1)/2). Reference: Elligator2.java square_root.
func elgSquareRoot(x *big.Int) *big.Int {
	t := new(big.Int).Exp(x, elgDivMinusP1Over4, elgP)
	result := new(big.Int).Exp(x, elgDivPlusP3Over8, elgP)
	// If t == -1 (mod p), multiply by sqrt(-1).
	t.Add(t, big.NewInt(1))
	if t.Cmp(elgP) == 0 {
		result.Mul(result, elgSqrtNegOne)
		result.Mod(result, elgP)
	}
	if result.Cmp(elgDivMinusP1Over2) > 0 {
		result.Sub(elgP, result)
	}
	return result
}

// Elligator2Encode encodes a 32-byte little-endian X25519 public key
// as a 32-byte representative. The two high bits of the last byte are
// randomized so the output looks like 256 random bits. Returns nil when
// the point cannot be encoded (about half of all keys).
// Reference: Elligator2.java encode(point).
func Elligator2Encode(pub []byte) []byte {
	// x = LE(pub)
	x := new(big.Int)
	var le [32]byte
	copy(le[:], pub)
	x.SetBytes(swapEndianness(le))
	if x.Cmp(elgP) >= 0 {
		return nil
	}
	var randByte [1]byte
	if _, err := rand.Read(randByte[:]); err != nil {
		return nil
	}
	alternative := randByte[0]&0x01 == 0
	if x.Sign() == 0 {
		alternative = false
	}
	// -ux(x + A) mod p must be a square.
	negPlusXA := new(big.Int).Neg(new(big.Int).Add(x, elgA))
	negUX := new(big.Int).Mul(elgU, x)
	negUX.Mod(negUX, elgP)
	negUX.Mul(negUX, negPlusXA)
	negUX.Mod(negUX, elgP)
	if legendre(negUX) == -1 {
		return nil
	}
	var r *big.Int
	if alternative {
		// r := -(x + A) / x
		xi := new(big.Int).ModInverse(x, elgP)
		r = xi.Mul(xi, negPlusXA)
	} else {
		// r := -x / (x + A): the inverse of -(x + A), reduced to [0, p).
		np := new(big.Int).Mod(negPlusXA, elgP)
		di := new(big.Int).ModInverse(np, elgP)
		r = di.Mul(di, x)
	}
	r.Mod(r, elgP)
	// r := square_root(r / u)
	r.Mul(r, elgInvU)
	r.Mod(r, elgP)
	r = elgSquareRoot(r)
	rv := leEncode(r)
	rv[31] |= randByte[0] & 0xc0
	return rv
}

// Elligator2Decode decodes a 32-byte representative into the X25519
// public key it encodes. Returns nil if the representative is invalid
// (only 10 of 2^254 are). Reference: Elligator2.java decode.
func Elligator2Decode(rep []byte) []byte {
	if len(rep) != 32 {
		return nil
	}
	// r = LE(rep with high two bits masked)
	var le [32]byte
	copy(le[:], rep)
	le[31] &= 0x3f
	r := new(big.Int).SetBytes(swapEndianness(le))
	if r.Cmp(elgDivMinusP1Over2) >= 0 {
		return nil
	}
	// v = -A / (1 + ur^2) mod p
	v := new(big.Int).Mul(r, r)
	v.Mod(v, elgP)
	v.Mul(v, elgU)
	v.Add(v, big.NewInt(1))
	v.Mod(v, elgP)
	v.ModInverse(v, elgP)
	v.Mul(v, elgNegA)
	v.Mod(v, elgP)
	// t = v^3 + Av^2 + v mod p
	t := new(big.Int).Mul(v, v)
	t.Mod(t, elgP)
	t.Mul(t, new(big.Int).Add(v, elgA))
	t.Add(t, v)
	t.Mod(t, elgP)
	var x *big.Int
	if legendre(t) == 1 {
		x = v
	} else {
		x = new(big.Int).Sub(elgP, v)
		x.Sub(x, elgA)
		x.Mod(x, elgP)
	}
	return leEncode(x)
}

// leEncode encodes x as 32 bytes little-endian.
func leEncode(x *big.Int) []byte {
	be := x.Bytes()
	out := make([]byte, 32)
	for i, b := range be {
		out[len(be)-1-i] = b
	}
	return out
}

// swapEndianness converts a little-endian [32]byte to big-endian order
// for big.Int.SetBytes.
func swapEndianness(le [32]byte) []byte {
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = le[31-i]
	}
	return out
}

// GenerateElligator2Keypair generates an X25519 keypair whose public key
// has a valid Elligator2 encoding, plus that encoding. Used for
// ephemeral keys in New Session messages.
func GenerateElligator2Keypair() (priv, pub, encoded []byte, err error) {
	for i := 0; i < 64; i++ {
		priv = make([]byte, 32)
		if _, err = rand.Read(priv); err != nil {
			return
		}
		pub, err = x25519Public(priv)
		if err != nil {
			return
		}
		encoded = Elligator2Encode(pub)
		if encoded != nil {
			return
		}
	}
	err = errNoElligator2
	return
}

var errNoElligator2 = &noElligator2Error{}

type noElligator2Error struct{}

func (*noElligator2Error) Error() string {
	return "garlic: could not generate an Elligator2-encodable key after 64 tries"
}

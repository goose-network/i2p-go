package data

import (
	"crypto/sha1"
	"math/big"
)

// I2P's fixed DSA-SHA1 parameters, so the network's legacy signatures
// verify. Reference: CryptoConstants.java (dsap/dsaq/dsag; p is the
// 1024-bit prime shared with the ElGamal group, q the 160-bit subgroup
// order, g the generator).
var (
	i2pDSAp, _ = new(big.Int).SetString("9c05b2aa960d9b97b8931963c9cc9e8c3026e9b8ed92fad0a69cc886d5bf8015fcadae31a0ad18fab3f01b00a358de237655c4964afaa2b337e96ad316b9fb1cc564b5aec5b69a9ff6c3e4548707fef8503d91dd8602e867e6d35d2235c1869ce2479c3b9d5401de04e0727fb33d6511285d4cf29538d9e3b6051f5b22cc1c93", 16)
	i2pDSAq, _ = new(big.Int).SetString("a5dfc28fef4ca1e286744cd8eed9d29d684046b7", 16)
	i2pDSAg, _ = new(big.Int).SetString("c1f4d27d40093b429e962d7223824e0bbc47e7c832a39236fc683af84889581075ff9082ed32353d4374d7301cda1d23c431f4698599dda02451824ff369752593647cc3ddc197de985e43d136cdcfc6bd5409cd2f450821142a5e6f8eb1c3ab5d0484b8129fcf17bce4f7f33321c3cb3dbb14a905e7b2b3e93be4708cbcc82", 16)
)

// verifyDSA_SHA1 checks a 40-byte I2P DSA signature (r‖s, fixed I2P
// parameters) over data with the destination's 128-byte signing key Y.
// Reference: DSAEngine.verifySig — SHA-1 of the signed data, w = s^-1 mod
// q, u1 = h·w mod q, u2 = r·w mod q, v = (g^u1 · y^u2 mod p) mod q, and
// v == r.
func verifyDSA_SHA1(sig, data, key []byte) bool {
	if len(sig) != 40 || len(key) < 128 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:20])
	s := new(big.Int).SetBytes(sig[20:40])
	y := new(big.Int).SetBytes(key[:128])
	if r.Sign() == 0 || s.Sign() == 0 {
		// An all-zero r/s fails the modInverse below; the Java rejects
		// it too (modInverse throws).
		return false
	}
	if r.Cmp(i2pDSAq) >= 0 || s.Cmp(i2pDSAq) >= 0 {
		return false
	}
	h := sha1.Sum(data)
	hb := new(big.Int).SetBytes(h[:])
	w := new(big.Int).ModInverse(s, i2pDSAq)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(hb, w)
	u1.Mod(u1, i2pDSAq)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, i2pDSAq)
	gu := new(big.Int).Exp(i2pDSAg, u1, i2pDSAp)
	yu := new(big.Int).Exp(y, u2, i2pDSAp)
	v := new(big.Int).Mul(gu, yu)
	v.Mod(v, i2pDSAp)
	v.Mod(v, i2pDSAq)
	return v.Cmp(r) == 0
}

// ElGamal 2048 key generation for client destinations.
//
// Java I2CP rejects EncType 4 (ECIES) client destinations — client
// destinations must carry an ElGamal key in the KeysAndCert — and the
// Java streaming parser (Packet.readPacket) advances the cursor by
// Destination.size(), which equals the wire length only when the
// encryption key is ElGamal (no key-certificate padding). So a client
// destination that interoperates with the reference router is
// ElGamal + Ed25519: ElGamal in the destination (routing identity),
// with the modern encryption key riding the LeaseSet2 instead.
//
// Reference: CryptoConstants.elgp/elgg (RFC 3526 2048-bit MODP group,
// g=2), KeyGenerator.generatePKIKeys (random exponent, y = g^x mod p,
// rectified to 256 big-endian bytes), KeyGenerator.PUBKEY_EXPONENT_SIZE_SHORT.

package data

import (
	"crypto/rand"
	"math/big"
)

// elgP is the RFC 3526 2048-bit MODP group prime (CryptoConstants.elgp).
var elgP = func() *big.Int {
	s := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("data: bad ElGamal prime")
	}
	return p
}()

// elgG is the group generator (CryptoConstants.elgg), 2.
var elgG = big.NewInt(2)

// GenerateElGamalKeyPair generates an ElGamal 2048 key pair: a random
// 226-bit exponent (KeyGenerator's short exponent, the default) and
// y = g^x mod p. The public key is rectified to exactly 256 big-endian
// bytes (SigUtil.rectify), the on-wire KeysAndCert encoding length.
func GenerateElGamalKeyPair() (pub, priv []byte, err error) {
	// 226 bits → a top byte with bits set, so x is in [2^225, 2^226).
	bits := 226
	x, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	if err != nil {
		return nil, nil, err
	}
	x = x.Or(x, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	y := new(big.Int).Exp(elgG, x, elgP)
	pub = rectify256(y)
	priv = rectify256(x)
	return pub, priv, nil
}

// rectify256 left-pads or truncates to exactly 256 bytes (unsigned
// big-endian), like SigUtil.rectify.
func rectify256(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 256 {
		b = b[len(b)-256:]
	}
	out := make([]byte, 256)
	copy(out[256-len(b):], b)
	return out
}

package data

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// Hash is a 32-byte SHA-256 identity hash.
type Hash [32]byte

// ReadHash reads a 32-byte hash.
func ReadHash(b []byte) (Hash, []byte, error) {
	var h Hash
	if len(b) < 32 {
		return h, nil, fmt.Errorf("hash: short buffer %d", len(b))
	}
	copy(h[:], b[:32])
	return h, b[32:], nil
}

// ToI2PBase64 returns the standard I2P base64 of the hash (netdb filenames).
func (h Hash) ToI2PBase64() string { return EncodeToI2PBase64(h[:]) }

// Equal reports whether two hashes match.
func (h Hash) Equal(o Hash) bool { return h == o }

// RouterIdentity is a router's cryptographic identity: encryption key,
// signing key, and certificate. Reference: KeysAndCert.java /
// RouterIdentity.java.
//
// The on-wire format is: 256-byte (legacy ElGamal length) encryption
// public key field, 128-byte (legacy DSA length) signing public key
// field, certificate. When the key certificate declares non-legacy
// lengths, the actual key data occupies the head of the legacy field and
// the remainder of the legacy field is padding (which must be preserved
// for the identity to round-trip, and is stored in Pad).
type RouterIdentity struct {
	EncKey     []byte // as declared by the enc type (32 for X25519, 256 for ElGamal)
	SigningKey []byte // as declared by the sig type (32 for Ed25519, 128 for DSA)
	SigType    SigType
	EncType    EncType
	Pad        []byte // legacy-field padding: 256-len(EncKey) + 128-len(SigningKey) - extra-key-data bytes
}

// ReadRouterIdentity parses a router identity.
// Reference: KeysAndCert.readBytes.
func ReadRouterIdentity(b []byte) (RouterIdentity, []byte, error) {
	// Legacy fixed fields: 256-byte crypto key, 128-byte signing key.
	const legacyEncLen, legacySigLen = 256, 128
	if len(b) < legacyEncLen+legacySigLen {
		return RouterIdentity{}, nil, fmt.Errorf("identity: short buffer %d", len(b))
	}
	encField := b[:legacyEncLen]
	sigField := b[legacyEncLen : legacyEncLen+legacySigLen]
	rest := b[legacyEncLen+legacySigLen:]
	cert, rest, err := ReadCertificate(rest)
	if err != nil {
		return RouterIdentity{}, nil, err
	}
	id := RouterIdentity{}
	if cert.Type == CertTypeKey {
		kc, err := cert.ParseKeyCertificate()
		if err != nil {
			return RouterIdentity{}, nil, err
		}
		id.SigType = kc.SigType
		id.EncType = kc.EncType
		sigLen := kc.SigType.PubkeyLen()
		encLen := kc.EncType.PubkeyLen()
		if sigLen < 0 || encLen < 0 {
			return RouterIdentity{}, nil, fmt.Errorf("identity: unknown key type sig=%d enc=%d", kc.SigType, kc.EncType)
		}
		if sigLen > legacySigLen {
			// Extra signing key data rides in the certificate payload.
			extra := kc.ExtraKeyData
			if len(extra) < sigLen-legacySigLen {
				return RouterIdentity{}, nil, fmt.Errorf("identity: key cert missing extra signing data")
			}
			id.SigningKey = append(append([]byte(nil), sigField...), extra[:sigLen-legacySigLen]...)
		}
		if encLen > legacyEncLen {
			return RouterIdentity{}, nil, fmt.Errorf("identity: unsupported enc key length %d", encLen)
		}
		id.EncKey = append([]byte(nil), encField[:encLen]...)
		// Reference KeysAndCert.readBytes + SigningPublicKey.toTypedKey:
		// the encryption key is LEFT-justified in the 256-byte legacy
		// field; the signing key is RIGHT-justified in the 128-byte
		// legacy field (toTypedKey takes the last newLen bytes), and
		// getPadding takes the first padLen bytes as padding.
		sigFieldUsed := sigLen
		if sigLen > legacySigLen {
			sigFieldUsed = legacySigLen
		}
		if sigLen < legacySigLen {
			id.SigningKey = append([]byte(nil), sigField[legacySigLen-sigLen:]...)
		} else {
			id.SigningKey = append([]byte(nil), sigField[:sigFieldUsed]...)
		}
		id.Pad = append(append([]byte(nil), encField[encLen:]...), sigField[:legacySigLen-sigFieldUsed]...)
	} else {
		// No key certificate: legacy ElGamal + DSA.
		id.SigType = SigDSA_SHA1
		id.EncType = EncElGamal2048
		id.EncKey = append([]byte(nil), encField...)
		id.SigningKey = append([]byte(nil), sigField...)
		id.Pad = nil
	}
	return id, rest, nil
}

// WriteTo appends the identity encoding. It round-trips the padding
// captured at parse time. Reference KeysAndCert.writeBytes: encryption
// key left-justified (trailing padding), signing key right-justified
// (leading padding), any signing-key excess rides in the key
// certificate payload.
func (id RouterIdentity) WriteTo(buf []byte) []byte {
	const legacyEncLen, legacySigLen = 256, 128
	encField := make([]byte, legacyEncLen)
	sigField := make([]byte, legacySigLen)
	copy(encField, id.EncKey)
	var extra []byte
	sigLen := len(id.SigningKey)
	sigFieldUsed := sigLen
	if sigLen <= legacySigLen {
		// Right-justify: key occupies the last sigLen bytes.
		copy(sigField[legacySigLen-sigLen:], id.SigningKey)
	} else {
		copy(sigField, id.SigningKey[:legacySigLen])
		extra = id.SigningKey[legacySigLen:]
	}
	encPadLen := legacyEncLen - len(id.EncKey)
	sigPadLen := legacySigLen - sigFieldUsed
	if len(id.Pad) == encPadLen+sigPadLen {
		// Restore the exact padding captured at parse time so the signed
		// bytes round-trip.
		copy(encField[len(id.EncKey):], id.Pad[:encPadLen])
		copy(sigField, id.Pad[encPadLen:])
	}
	buf = append(buf, encField...)
	buf = append(buf, sigField...)
	kc := KeyCertificate{SigType: id.SigType, EncType: id.EncType, ExtraKeyData: extra}
	return kc.WriteTo(buf)
}

// RouterHash computes the router identity hash: SHA-256 over the
// identity encoding.
func (id RouterIdentity) RouterHash() Hash {
	var buf []byte
	buf = id.WriteTo(buf)
	return Hash(sha256.Sum256(buf))
}

// RouterAddress is one published transport address.
// Reference: RouterAddress.java: cost (1B), expiration date (8B),
// transport style string, options.
type RouterAddress struct {
	Cost           int
	Expiration     time.Time
	TransportStyle string
	Options        map[string]string
}

// ReadRouterAddress parses a router address.
func ReadRouterAddress(b []byte) (RouterAddress, []byte, error) {
	if len(b) < 1+DATE_LENGTH {
		return RouterAddress{}, nil, fmt.Errorf("address: short buffer")
	}
	a := RouterAddress{Cost: int(b[0])}
	exp, err := ReadDate(b[1:], 0)
	if err != nil {
		return RouterAddress{}, nil, err
	}
	a.Expiration = exp
	rest := b[1+DATE_LENGTH:]
	style, rest, err := readI2PString(rest)
	if err != nil {
		return RouterAddress{}, nil, err
	}
	a.TransportStyle = style
	props, rest, err := ReadProperties(rest)
	if err != nil {
		return RouterAddress{}, nil, err
	}
	a.Options = props
	return a, rest, nil
}

// WriteTo appends the address encoding.
func (a RouterAddress) WriteTo(buf []byte) []byte {
	buf = append(buf, byte(a.Cost))
	buf = append(buf, AppendDate(a.Expiration)...)
	buf = appendI2PString(buf, a.TransportStyle)
	return AppendProperties(buf, a.Options)
}

// RouterInfo is a router's published descriptor.
// Reference: RouterInfo.java: identity, published (8B ms), address
// count, addresses, peer count (0), options, signature.
type RouterInfo struct {
	Identity  RouterIdentity
	Published time.Time
	Addresses []RouterAddress
	Options   map[string]string
	Signature []byte
	raw       []byte // signed bytes (everything before the signature)
}

// ReadRouterInfo parses a router info. If verify is true the signature
// is checked with the identity's signing key.
func ReadRouterInfo(b []byte, verify bool) (RouterInfo, error) {
	ri := RouterInfo{}
	rest := b
	id, rest, err := ReadRouterIdentity(rest)
	if err != nil {
		return ri, err
	}
	ri.Identity = id
	if len(rest) < 8+1 {
		return ri, fmt.Errorf("routerinfo: truncated after identity")
	}
	pub, err := ReadLong(rest, 0, 8)
	if err != nil {
		return ri, err
	}
	ri.Published = time.UnixMilli(int64(pub))
	rest = rest[8:]
	nAddr := int(rest[0])
	rest = rest[1:]
	if nAddr > 16 {
		return ri, fmt.Errorf("routerinfo: too many addresses %d", nAddr)
	}
	for i := 0; i < nAddr; i++ {
		var a RouterAddress
		a, rest, err = ReadRouterAddress(rest)
		if err != nil {
			return ri, err
		}
		ri.Addresses = append(ri.Addresses, a)
	}
	if len(rest) < 1 {
		return ri, fmt.Errorf("routerinfo: truncated at peer count")
	}
	nPeers := int(rest[0])
	rest = rest[1:]
	if nPeers > 0 {
		if len(rest) < nPeers*32 {
			return ri, fmt.Errorf("routerinfo: truncated peer list")
		}
		rest = rest[nPeers*32:]
	}
	var props map[string]string
	props, rest, err = ReadProperties(rest)
	if err != nil {
		return ri, err
	}
	ri.Options = props
	if len(rest) < len(ri.Identity.SigningKey) {
		// sig length depends on type; read below
	}
	sigLen := sigLenFor(id.SigType)
	if len(rest) < sigLen {
		return ri, fmt.Errorf("routerinfo: truncated signature (%d < %d)", len(rest), sigLen)
	}
	ri.Signature = append([]byte(nil), rest[:sigLen]...)
	ri.raw = append([]byte(nil), b[:len(b)-len(rest)]...)
	if verify {
		if err := ri.Verify(); err != nil {
			return ri, err
		}
	}
	return ri, nil
}

func sigLenFor(t SigType) int {
	switch t {
	case SigDSA_SHA1:
		return 40
	case SigECDSA_SHA256_P256:
		return 64
	case SigECDSA_SHA384_P384:
		return 96
	case SigECDSA_SHA512_P521:
		return 132
	case SigRSA_SHA256_2048:
		return 256
	case SigRSA_SHA384_3072:
		return 384
	case SigRSA_SHA512_4096:
		return 512
	case SigEdDSA_SHA512_Ed25519, SigRedDSA_SHA512_Ed25519:
		return 64
	}
	return 0
}

// Verify checks the router info signature.
func (ri *RouterInfo) Verify() error {
	switch ri.Identity.SigType {
	case SigEdDSA_SHA512_Ed25519:
		if len(ri.Identity.SigningKey) != ed25519.PublicKeySize {
			return fmt.Errorf("routerinfo: bad ed25519 key length %d", len(ri.Identity.SigningKey))
		}
		if !ed25519.Verify(ed25519.PublicKey(ri.Identity.SigningKey), ri.signedBytes(), ri.Signature) {
			return fmt.Errorf("routerinfo: signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("routerinfo: unsupported sig type %d for verification", ri.Identity.SigType)
	}
}

// Sign signs the router info in place with an Ed25519 private key
// matching the identity's signing key. Reference: RouterInfo.sign
// (signs everything before the signature).
func (ri *RouterInfo) Sign(priv ed25519.PrivateKey) error {
	if ri.Identity.SigType != SigEdDSA_SHA512_Ed25519 {
		return fmt.Errorf("routerinfo: unsupported sig type %d for signing", ri.Identity.SigType)
	}
	ri.Signature = nil
	ri.raw = nil
	ri.Signature = ed25519.Sign(priv, ri.signedBytes())
	return nil
}

// signedBytes serializes the router info without the signature.
func (ri *RouterInfo) signedBytes() []byte {
	if ri.raw != nil {
		return ri.raw
	}
	var buf []byte
	buf = ri.Identity.WriteTo(buf)
	buf = append(buf, AppendLong(8, uint64(ri.Published.UnixMilli()))...)
	buf = append(buf, byte(len(ri.Addresses)))
	for _, a := range ri.Addresses {
		buf = a.WriteTo(buf)
	}
	buf = append(buf, 0) // peer count
	buf = AppendProperties(buf, ri.Options)
	return buf
}

// Bytes returns the full signed encoding (data + signature).
func (ri *RouterInfo) Bytes() []byte {
	return append(ri.signedBytes(), ri.Signature...)
}

// RouterHash returns SHA-256 over the identity encoding.
func (ri *RouterInfo) RouterHash() Hash { return ri.Identity.RouterHash() }

// NetDBFileName is the base64 router hash (the netdb file name).
func (ri *RouterInfo) NetDBFileName() string { return ri.RouterHash().ToI2PBase64() }

// SortedOptionKeys returns the option keys sorted (debug helper).
func (ri *RouterInfo) SortedOptionKeys() []string {
	keys := make([]string, 0, len(ri.Options))
	for k := range ri.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = bytes.Equal

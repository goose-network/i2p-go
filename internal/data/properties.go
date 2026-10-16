package data

import (
	"bytes"
	"fmt"
	"sort"
)

// SigType identifies a signing algorithm. Reference: SigType.java.
type SigType int

const (
	SigDSA_SHA1              SigType = 0
	SigECDSA_SHA256_P256     SigType = 1
	SigECDSA_SHA384_P384     SigType = 2
	SigECDSA_SHA512_P521     SigType = 3
	SigRSA_SHA256_2048       SigType = 4
	SigRSA_SHA384_3072       SigType = 5
	SigRSA_SHA512_4096       SigType = 6
	SigEdDSA_SHA512_Ed25519  SigType = 7 // the common case on today's network
	SigRedDSA_SHA512_Ed25519 SigType = 11
)

// PubkeyLen returns the encoded public key length for the sig type.
func (t SigType) PubkeyLen() int {
	switch t {
	case SigDSA_SHA1:
		return 128
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
		return 32
	}
	return -1
}

// EncType identifies an asymmetric encryption algorithm. Reference: EncType.java.
type EncType int

const (
	EncElGamal2048  EncType = 0
	EncECIES_X25519 EncType = 4
)

// PubkeyLen returns the encoded public key length for the enc type.
func (t EncType) PubkeyLen() int {
	switch t {
	case EncElGamal2048:
		return 256
	case EncECIES_X25519:
		return 32
	}
	return -1
}

// Certificate types. Reference: Certificate.java.
const (
	CertTypeNull = 0
	CertTypeKey  = 5
)

// Certificate is an I2P certificate blob. Only the key certificate
// (type 5) matters to us; the others are carried opaque.
type Certificate struct {
	Type    int
	Payload []byte
}

// ReadCertificate parses a certificate at the head of b.
// Reference: Certificate.readBytes.
func ReadCertificate(b []byte) (Certificate, []byte, error) {
	if len(b) < 3 {
		return Certificate{}, nil, fmt.Errorf("certificate: short buffer %d", len(b))
	}
	t := int(b[0])
	plen := int(b[1])<<8 | int(b[2])
	if len(b) < 3+plen {
		return Certificate{}, nil, fmt.Errorf("certificate: payload %d exceeds buffer %d", plen, len(b))
	}
	var payload []byte
	if plen > 0 {
		payload = append([]byte(nil), b[3:3+plen]...)
	}
	return Certificate{Type: t, Payload: payload}, b[3+plen:], nil
}

// WriteCertificate appends the certificate encoding.
func (c Certificate) WriteTo(buf []byte) []byte {
	buf = append(buf, byte(c.Type))
	buf = append(buf, byte(len(c.Payload)>>8), byte(len(c.Payload)))
	return append(buf, c.Payload...)
}

// KeyCertificate is the parsed view of a type-5 certificate.
// Reference: KeyCertificate.java. HEADER_LENGTH=4: sig type (2 bytes,
// big endian), enc type (2 bytes, big endian), followed by extra key
// data for key types that do not fit the legacy 256/128-byte fields.
type KeyCertificate struct {
	SigType      SigType
	EncType      EncType
	ExtraKeyData []byte
}

// ParseKeyCertificate interprets a type-5 certificate payload.
func (c Certificate) ParseKeyCertificate() (KeyCertificate, error) {
	if c.Type != CertTypeKey {
		return KeyCertificate{}, fmt.Errorf("not a key certificate: type %d", c.Type)
	}
	p := c.Payload
	if len(p) < 4 {
		return KeyCertificate{}, fmt.Errorf("key certificate payload too short: %d", len(p))
	}
	kc := KeyCertificate{
		SigType:      SigType(int(p[0])<<8 | int(p[1])),
		EncType:      EncType(int(p[2])<<8 | int(p[3])),
		ExtraKeyData: append([]byte(nil), p[4:]...),
	}
	return kc, nil
}

// WriteTo re-encodes the key certificate as a Certificate.
func (k KeyCertificate) WriteTo(buf []byte) []byte {
	payload := make([]byte, 4+len(k.ExtraKeyData))
	payload[0] = byte(int(k.SigType) >> 8)
	payload[1] = byte(int(k.SigType))
	payload[2] = byte(int(k.EncType) >> 8)
	payload[3] = byte(int(k.EncType))
	copy(payload[4:], k.ExtraKeyData)
	return Certificate{Type: CertTypeKey, Payload: payload}.WriteTo(buf)
}

// ReadProperties parses an I2P property block: 2-byte size, then
// key=value; entries. Reference: DataHelper.readProperties.
func ReadProperties(b []byte) (map[string]string, []byte, error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("properties: short buffer")
	}
	size := int(b[0])<<8 | int(b[1])
	if len(b) < 2+size {
		return nil, nil, fmt.Errorf("properties: size %d exceeds buffer %d", size, len(b))
	}
	props := map[string]string{}
	rest := b[2+size:]
	block := b[2 : 2+size]
	for len(block) > 0 {
		var key, val string
		var err error
		key, block, err = readI2PString(block)
		if err != nil {
			return nil, nil, err
		}
		if len(block) == 0 || block[0] != '=' {
			return nil, nil, fmt.Errorf("properties: expected '='")
		}
		block = block[1:]
		val, block, err = readI2PString(block)
		if err != nil {
			return nil, nil, err
		}
		if len(block) == 0 || block[0] != ';' {
			return nil, nil, fmt.Errorf("properties: expected ';'")
		}
		block = block[1:]
		props[key] = val
	}
	return props, rest, nil
}

// AppendProperties appends an I2P property block, keys sorted.
// Reference: DataHelper.writeProperties.
func AppendProperties(buf []byte, props map[string]string) []byte {
	if len(props) == 0 {
		return append(buf, 0, 0)
	}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var block []byte
	for _, k := range keys {
		block = appendI2PString(block, k)
		block = append(block, '=')
		block = appendI2PString(block, props[k])
		block = append(block, ';')
	}
	buf = append(buf, byte(len(block)>>8), byte(len(block)))
	return append(buf, block...)
}

// readI2PString reads a length-prefixed (1 byte) string.
// Reference: DataHelper.readString.
func readI2PString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, fmt.Errorf("string: empty buffer")
	}
	n := int(b[0])
	if len(b) < 1+n {
		return "", nil, fmt.Errorf("string: length %d exceeds buffer %d", n, len(b)-1)
	}
	return string(b[1 : 1+n]), b[1+n:], nil
}

// appendI2PString appends a length-prefixed string.
func appendI2PString(buf []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	buf = append(buf, byte(len(s)))
	return append(buf, s...)
}

// ReadString reads a length-prefixed string from the head of b.
func ReadString(b []byte) (string, []byte, error) { return readI2PString(b) }

// AppendString appends a length-prefixed string to buf.
func AppendString(buf []byte, s string) []byte { return appendI2PString(buf, s) }

var _ = bytes.Equal

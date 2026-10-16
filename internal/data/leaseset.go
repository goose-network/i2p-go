// LeaseSet structures: the Destination, Lease/Lease2, LeaseSet2 and the
// legacy LeaseSet. Reference: Destination.java, KeysAndCert.java,
// Lease2.java, LeaseSet2.java, LeaseSet.java in the I2P reference router
// (../i2p.i2p).

package data

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// Destination is a client destination. On the wire it is a KeysAndCert
// — byte-for-byte the same layout as RouterIdentity — so it shares that
// type. Reference: Destination.java (extends KeysAndCert).
type Destination = RouterIdentity

// ReadDestination parses a destination. Reference: KeysAndCert.readBytes.
func ReadDestination(b []byte) (Destination, []byte, error) {
	return ReadRouterIdentity(b)
}

// DestinationHash is the SHA-256 of the destination's full encoding: the
// netdb lookup key for its LeaseSet, and the base of the .b32.i2p
// hostname. Reference: Destination.calculateHash.
func DestinationHash(d Destination) Hash { return d.RouterHash() }

// Base32Address returns the .b32.i2p hostname for the destination:
// 52 lowercase base32 characters of the destination hash.
// Reference: Destination.toBase32 (getHash().toBase32()).
func (id RouterIdentity) Base32Address() string {
	h := id.RouterHash()
	return EncodeToI2PBase32(h[:])[:52] + ".b32.i2p"
}

// LeaseSet2 flags. Reference: LeaseSet2.java.
const (
	LS2FlagOfflineKeys = 0x01
	LS2FlagUnpublished = 0x02
	LS2FlagBlinded     = 0x04
)

// MaxLeases is the maximum lease count. Reference: LeaseSet.MAX_LEASES.
const MaxLeases = 16

// Lease is a Lease2 (proposal 123): gateway hash, tunnel ID, and a
// 4-byte end date (unix seconds). 40 bytes. Reference: Lease2.java.
type Lease struct {
	Gateway  Hash
	TunnelID uint32
	End      time.Time
}

// ReadLease parses a 40-byte Lease2.
func ReadLease(b []byte) (Lease, []byte, error) {
	var l Lease
	if len(b) < 40 {
		return l, nil, fmt.Errorf("lease2: short buffer %d", len(b))
	}
	copy(l.Gateway[:], b[:32])
	l.TunnelID = uint32(b[32])<<24 | uint32(b[33])<<16 | uint32(b[34])<<8 | uint32(b[35])
	sec := uint32(b[36])<<24 | uint32(b[37])<<16 | uint32(b[38])<<8 | uint32(b[39])
	l.End = time.Unix(int64(sec), 0)
	return l, b[40:], nil
}

// WriteTo appends the 40-byte Lease2 encoding.
func (l Lease) WriteTo(buf []byte) []byte {
	buf = append(buf, l.Gateway[:]...)
	buf = append(buf, byte(l.TunnelID>>24), byte(l.TunnelID>>16), byte(l.TunnelID>>8), byte(l.TunnelID))
	sec := uint32(l.End.Unix())
	buf = append(buf, byte(sec>>24), byte(sec>>16), byte(sec>>8), byte(sec))
	return buf
}

// PublicKey is an LS2 encryption key entry: an enc type plus raw key
// bytes. Unknown enc types are carried through with their code.
// Reference: PublicKey.java.
type PublicKey struct {
	EncType EncType
	Key     []byte
	RawType int  // nonzero when EncType is unknown
	ElGamal bool // legacy LS2 special case: encType 0 key, length implied
}

// LeaseSet2 is a LeaseSet2 (proposal 123, DatabaseEntry type 3).
// Reference: LeaseSet2.java readBytes/writeBytes/sign/verifySignature.
type LeaseSet2 struct {
	Destination Destination
	Published   time.Time
	Expires     time.Time
	Flags       uint16

	// Offline signing block (FLAG_OFFLINE_KEYS).
	TransientExpires time.Time
	TransientSigType SigType
	TransientSPK     []byte
	OfflineSignature []byte

	Options        map[string]string
	EncryptionKeys []PublicKey
	Leases         []Lease
	Signature      []byte

	raw []byte // everything before the signature
}

// ReadLeaseSet2 parses a LeaseSet2. If verify is true the signature is
// checked (online with the destination SPK, offline with the transient
// SPK after verifying the offline signature).
func ReadLeaseSet2(b []byte, verify bool) (*LeaseSet2, error) {
	ls := &LeaseSet2{}
	dest, rest, err := ReadDestination(b)
	if err != nil {
		return nil, fmt.Errorf("ls2: destination: %w", err)
	}
	ls.Destination = dest
	if len(rest) < 8 {
		return nil, fmt.Errorf("ls2: short header %d", len(rest))
	}
	pub := uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
	ls.Published = time.Unix(int64(pub), 0)
	delta := uint16(rest[4])<<8 | uint16(rest[5])
	ls.Expires = ls.Published.Add(time.Duration(delta) * time.Second)
	ls.Flags = uint16(rest[6])<<8 | uint16(rest[7])
	rest = rest[8:]
	if ls.Flags&LS2FlagOfflineKeys != 0 {
		rest, err = ls.readOffline(rest)
		if err != nil {
			return nil, err
		}
	}
	props, rest, err := ReadProperties(rest)
	if err != nil {
		return nil, fmt.Errorf("ls2: options: %w", err)
	}
	ls.Options = props
	if len(rest) < 1 {
		return nil, fmt.Errorf("ls2: truncated at key count")
	}
	numKeys := int(rest[0])
	rest = rest[1:]
	if numKeys <= 0 || numKeys > 8 {
		return nil, fmt.Errorf("ls2: bad key count %d", numKeys)
	}
	for i := 0; i < numKeys; i++ {
		if len(rest) < 4 {
			return nil, fmt.Errorf("ls2: truncated at key %d", i)
		}
		encType := int(rest[0])<<8 | int(rest[1])
		encLen := int(rest[2])<<8 | int(rest[3])
		rest = rest[4:]
		var pk PublicKey
		if encType == 0 {
			// ElGamal: the length field is ignored, exactly 256 bytes
			// are consumed. Reference: LeaseSet2.java readBytes
			// (PublicKey.create(in)).
			if len(rest) < 256 {
				return nil, fmt.Errorf("ls2: short elgamal key")
			}
			pk = PublicKey{EncType: EncElGamal2048, Key: append([]byte(nil), rest[:256]...), ElGamal: true}
			rest = rest[256:]
		} else {
			if len(rest) < encLen {
				return nil, fmt.Errorf("ls2: key %d length %d exceeds buffer", i, encLen)
			}
			pk = PublicKey{EncType: EncType(encType), Key: append([]byte(nil), rest[:encLen]...)}
			rest = rest[encLen:]
		}
		ls.EncryptionKeys = append(ls.EncryptionKeys, pk)
	}
	if len(rest) < 1 {
		return nil, fmt.Errorf("ls2: truncated at lease count")
	}
	numLeases := int(rest[0])
	rest = rest[1:]
	if numLeases > MaxLeases {
		return nil, fmt.Errorf("ls2: too many leases %d", numLeases)
	}
	for i := 0; i < numLeases; i++ {
		var l Lease
		l, rest, err = ReadLease(rest)
		if err != nil {
			return nil, fmt.Errorf("ls2: lease %d: %w", i, err)
		}
		ls.Leases = append(ls.Leases, l)
	}
	sigType := dest.SigType
	if ls.Flags&LS2FlagOfflineKeys != 0 {
		sigType = ls.TransientSigType
	}
	sigLen := sigLenFor(sigType)
	if sigLen <= 0 {
		return nil, fmt.Errorf("ls2: unsupported sig type %d", sigType)
	}
	if len(rest) < sigLen {
		return nil, fmt.Errorf("ls2: truncated signature (%d < %d)", len(rest), sigLen)
	}
	ls.Signature = append([]byte(nil), rest[:sigLen]...)
	ls.raw = append([]byte(nil), b[:len(b)-sigLen]...)
	if verify {
		if err := ls.Verify(); err != nil {
			return nil, err
		}
	}
	return ls, nil
}

// readOffline parses the offline signing block.
// Reference: LeaseSet2.java readOfflineBytes.
func (ls *LeaseSet2) readOffline(rest []byte) ([]byte, error) {
	if len(rest) < 6 {
		return nil, fmt.Errorf("ls2: short offline block")
	}
	expires := uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
	ls.TransientExpires = time.Unix(int64(expires), 0)
	ls.TransientSigType = SigType(int(rest[4])<<8 | int(rest[5]))
	rest = rest[6:]
	spkLen := ls.TransientSigType.PubkeyLen()
	if spkLen < 0 {
		return nil, fmt.Errorf("ls2: unknown transient sig type %d", ls.TransientSigType)
	}
	if len(rest) < spkLen {
		return nil, fmt.Errorf("ls2: short transient key")
	}
	ls.TransientSPK = append([]byte(nil), rest[:spkLen]...)
	rest = rest[spkLen:]
	// The offline signature is by the destination's SPK.
	offLen := sigLenFor(ls.Destination.SigType)
	if len(rest) < offLen {
		return nil, fmt.Errorf("ls2: short offline signature")
	}
	ls.OfflineSignature = append([]byte(nil), rest[:offLen]...)
	return rest[offLen:], nil
}

// offlineBlockBytes encodes the offline signing block.
func (ls *LeaseSet2) offlineBlockBytes() []byte {
	var out []byte
	sec := uint32(ls.TransientExpires.Unix())
	out = append(out, byte(sec>>24), byte(sec>>16), byte(sec>>8), byte(sec))
	st := int(ls.TransientSigType)
	out = append(out, byte(st>>8), byte(st))
	out = append(out, ls.TransientSPK...)
	return out
}

// Sign signs the LeaseSet2 in place. The signature covers the type byte
// (3) followed by everything before the signature.
// Reference: LeaseSet2.java sign (LS2 sigs cover the type).
func (ls *LeaseSet2) Sign(priv ed25519.PrivateKey) error {
	if ls.Destination.SigType != SigEdDSA_SHA512_Ed25519 {
		return fmt.Errorf("ls2: unsupported sig type %d for signing", ls.Destination.SigType)
	}
	ls.raw = nil
	msg := append([]byte{3}, ls.signedBytes()...)
	ls.Signature = ed25519.Sign(priv, msg)
	return nil
}

// signedBytes returns the encoding without the signature.
func (ls *LeaseSet2) signedBytes() []byte {
	if ls.raw != nil {
		return ls.raw
	}
	var buf []byte
	buf = ls.Destination.WriteTo(buf)
	pub := uint32(ls.Published.Unix())
	buf = append(buf, byte(pub>>24), byte(pub>>16), byte(pub>>8), byte(pub))
	delta := uint32(ls.Expires.Sub(ls.Published) / time.Second)
	buf = append(buf, byte(delta>>8), byte(delta))
	fl := uint16(ls.Flags)
	buf = append(buf, byte(fl>>8), byte(fl))
	if ls.Flags&LS2FlagOfflineKeys != 0 {
		buf = append(buf, ls.offlineBlockBytes()...)
		buf = append(buf, ls.OfflineSignature...)
	}
	buf = AppendProperties(buf, ls.Options)
	buf = append(buf, byte(len(ls.EncryptionKeys)))
	for _, pk := range ls.EncryptionKeys {
		t := pk.EncType
		if pk.RawType != 0 {
			t = EncType(pk.RawType)
		}
		te := int(t)
		buf = append(buf, byte(te>>8), byte(te))
		// ElGamal keys keep the implied 256-byte length on write.
		kl := len(pk.Key)
		if pk.ElGamal {
			kl = 256
		}
		buf = append(buf, byte(kl>>8), byte(kl))
		buf = append(buf, pk.Key...)
	}
	buf = append(buf, byte(len(ls.Leases)))
	for _, l := range ls.Leases {
		buf = l.WriteTo(buf)
	}
	return buf
}

// Bytes returns the full encoding including the signature.
func (ls *LeaseSet2) Bytes() []byte {
	return append(ls.signedBytes(), ls.Signature...)
}

// Verify checks the LeaseSet2 signature.
// Reference: LeaseSet2.java verifySignature.
func (ls *LeaseSet2) Verify() error {
	if ls.Signature == nil {
		return fmt.Errorf("ls2: not signed")
	}
	msg := append([]byte{3}, ls.signedBytes()...)
	if ls.Flags&LS2FlagOfflineKeys != 0 {
		if time.Now().After(ls.TransientExpires) {
			return fmt.Errorf("ls2: offline signature expired")
		}
		// The offline signature covers expires || sig type || transient
		// SPK, signed by the destination's real SPK.
		// Reference: LeaseSet2.java verifyOfflineSignature.
		if len(ls.Destination.SigningKey) != ed25519.PublicKeySize {
			return fmt.Errorf("ls2: bad destination signing key")
		}
		if !ed25519.Verify(ed25519.PublicKey(ls.Destination.SigningKey), ls.offlineBlockBytes(), ls.OfflineSignature) {
			return fmt.Errorf("ls2: offline signature verification failed")
		}
		if len(ls.TransientSPK) != ed25519.PublicKeySize {
			return fmt.Errorf("ls2: bad transient key length")
		}
		if !ed25519.Verify(ed25519.PublicKey(ls.TransientSPK), msg, ls.Signature) {
			return fmt.Errorf("ls2: signature verification failed")
		}
		return nil
	}
	if len(ls.Destination.SigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("ls2: bad destination signing key length %d", len(ls.Destination.SigningKey))
	}
	if !ed25519.Verify(ed25519.PublicKey(ls.Destination.SigningKey), msg, ls.Signature) {
		return fmt.Errorf("ls2: signature verification failed")
	}
	return nil
}

// LeaseSet is the legacy LS1 (DatabaseEntry type 1). Only parsing is
// implemented; the client publishes LS2. Reference: LeaseSet.java
// readBytes/writeBytes.
type LeaseSet struct {
	Destination   Destination
	EncryptionKey []byte // length per the destination's EncType
	SigningKey    []byte // same SigType as the destination
	Leases        []Lease1
	Signature     []byte
}

// Lease1 is a legacy 44-byte lease: gateway 32, tunnel ID 4, end 8B ms.
// Reference: Lease.java.
type Lease1 struct {
	Gateway  Hash
	TunnelID uint32
	End      time.Time
}

// ReadLeaseSet parses a legacy LeaseSet (LS1), verifying the signature.
func ReadLeaseSet(b []byte, verify bool) (*LeaseSet, error) {
	ls := &LeaseSet{}
	dest, rest, err := ReadDestination(b)
	if err != nil {
		return nil, fmt.Errorf("ls1: destination: %w", err)
	}
	ls.Destination = dest
	encLen := dest.EncType.PubkeyLen()
	sigPubLen := dest.SigType.PubkeyLen()
	sigLen := sigLenFor(dest.SigType)
	if encLen < 0 || sigPubLen < 0 || sigLen <= 0 {
		return nil, fmt.Errorf("ls1: unsupported key types enc=%d sig=%d", dest.EncType, dest.SigType)
	}
	if len(rest) < encLen+sigPubLen+1 {
		return nil, fmt.Errorf("ls1: short buffer")
	}
	ls.EncryptionKey = append([]byte(nil), rest[:encLen]...)
	rest = rest[encLen:]
	ls.SigningKey = append([]byte(nil), rest[:sigPubLen]...)
	rest = rest[sigPubLen:]
	nLeases := int(rest[0])
	rest = rest[1:]
	if nLeases > MaxLeases {
		return nil, fmt.Errorf("ls1: too many leases %d", nLeases)
	}
	for i := 0; i < nLeases; i++ {
		if len(rest) < 44 {
			return nil, fmt.Errorf("ls1: short lease %d", i)
		}
		var l Lease1
		copy(l.Gateway[:], rest[:32])
		l.TunnelID = uint32(rest[32])<<24 | uint32(rest[33])<<16 | uint32(rest[34])<<8 | uint32(rest[35])
		end, err := ReadLong(rest, 36, 8)
		if err != nil {
			return nil, err
		}
		l.End = time.UnixMilli(int64(end))
		ls.Leases = append(ls.Leases, l)
		rest = rest[44:]
	}
	if len(rest) < sigLen {
		return nil, fmt.Errorf("ls1: truncated signature")
	}
	ls.Signature = append([]byte(nil), rest[:sigLen]...)
	if verify {
		if dest.SigType != SigEdDSA_SHA512_Ed25519 {
			return nil, fmt.Errorf("ls1: unsupported sig type %d for verification", dest.SigType)
		}
		msg := b[:len(b)-sigLen]
		if !ed25519.Verify(ed25519.PublicKey(dest.SigningKey), msg, ls.Signature) {
			return nil, fmt.Errorf("ls1: signature verification failed")
		}
	}
	return ls, nil
}

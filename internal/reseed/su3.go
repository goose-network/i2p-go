// Package reseed implements SU3 reseed-bundle parsing and the HTTPS
// reseed fetch itself.
//
// This package mirrors the Java reference implementation files
// core/java/src/net/i2p/crypto/SU3File.java and
// router/java/src/net/i2p/router/networkdb/reseed/Reseeder.java in the
// I2P reference router (../i2p.i2p).
package reseed

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/goose-network/i2p-go/internal/data"
)

// SU3 file format constants. Reference: SU3File.java.
const (
	SU3Magic = "I2Psu3"

	SU3FileVersion = 0

	// SU3 file types (advisory).
	SU3TypeZIP = 0

	// SU3 content types.
	SU3ContentUnknown = 0
	SU3ContentRouter  = 1
	SU3ContentPlugin  = 2
	SU3ContentReseed  = 3
	SU3ContentNews    = 4

	// VERSION_OFFSET is the offset of the version string in the header.
	SU3VersionOffset = 40

	// Minimum bytes in the version string field.
	SU3MinVersionBytes = 16
)

// SU3 is a parsed (not yet verified) SU3 bundle.
type SU3 struct {
	SigType         data.SigType
	SignatureLength int
	VersionLength   int
	SignerLength    int
	ContentLength   int64
	FileType        int
	ContentType     int
	Version         string
	Signer          string

	Content   []byte // the signed content bytes
	Signature []byte
	covered   []byte // all bytes covered by the signature (header + content)
}

// ParseSU3 parses an SU3 file without verifying the signature.
// Reference: SU3File.verifyHeader + verifyAndMigrate.
func ParseSU3(b []byte) (*SU3, error) {
	if len(b) < SU3VersionOffset {
		return nil, fmt.Errorf("su3: short file %d", len(b))
	}
	if string(b[:6]) != SU3Magic {
		return nil, fmt.Errorf("su3: bad magic %q", string(b[:6]))
	}
	if b[7] != SU3FileVersion {
		return nil, fmt.Errorf("su3: bad file version %d", b[7])
	}
	s := &SU3{}
	s.SigType = data.SigType(int(b[8])<<8 | int(b[9]))
	s.SignatureLength = int(b[10])<<8 | int(b[11])
	// b[12] unused
	s.VersionLength = int(b[13])
	if s.VersionLength < SU3MinVersionBytes {
		return nil, fmt.Errorf("su3: bad version length %d", s.VersionLength)
	}
	// b[14] unused
	s.SignerLength = int(b[15])
	if s.SignerLength <= 0 {
		return nil, fmt.Errorf("su3: bad signer length %d", s.SignerLength)
	}
	s.ContentLength = int64(b[16])<<56 | int64(b[17])<<48 | int64(b[18])<<40 | int64(b[19])<<32 |
		int64(b[20])<<24 | int64(b[21])<<16 | int64(b[22])<<8 | int64(b[23])
	if s.ContentLength <= 0 {
		return nil, fmt.Errorf("su3: bad content length %d", s.ContentLength)
	}
	// b[24] unused
	s.FileType = int(b[25])
	// b[26] unused
	s.ContentType = int(b[27])
	// b[28:40] reserved
	vend := SU3VersionOffset + s.VersionLength
	if len(b) < vend+s.SignerLength {
		return nil, fmt.Errorf("su3: truncated version/signer strings")
	}
	vb := b[SU3VersionOffset:vend]
	if i := bytes.IndexByte(vb, 0); i >= 0 {
		vb = vb[:i]
	}
	s.Version = string(vb)
	s.Signer = string(b[vend : vend+s.SignerLength])
	contentStart := vend + s.SignerLength
	contentEnd := contentStart + int(s.ContentLength)
	sigLen := s.SigType.PubkeyLen()
	_ = sigLen
	if len(b) < contentEnd+s.SignatureLength {
		return nil, fmt.Errorf("su3: truncated content/signature (%d < %d)", len(b), contentEnd+s.SignatureLength)
	}
	s.Content = b[contentStart:contentEnd]
	s.covered = b[:contentEnd]
	s.Signature = b[contentEnd : contentEnd+s.SignatureLength]
	if len(b) != contentEnd+s.SignatureLength {
		return nil, fmt.Errorf("su3: %d trailing bytes", len(b)-(contentEnd+s.SignatureLength))
	}
	return s, nil
}

// Verify checks the SU3 signature against a set of trusted reseed
// signer certificates. Reference: SU3File.verifyAndMigrate + DirKeyRing.
func (s *SU3) Verify(trustedKeys map[string]crypto.PublicKey) error {
	switch s.SigType {
	case data.SigEdDSA_SHA512_Ed25519:
		key, ok := trustedKeys[s.Signer].(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("su3: unknown signer %q", s.Signer)
		}
		if !ed25519.Verify(key, s.covered, s.Signature) {
			return fmt.Errorf("su3: signature verification failed for %s", s.Signer)
		}
		return nil
	case data.SigRSA_SHA512_4096:
		key, ok := trustedKeys[s.Signer].(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("su3: unknown signer %q", s.Signer)
		}
		h := sha512.Sum512(s.covered)
		if err := verifyRSAI2P(key, h[:], s.Signature); err != nil {
			return fmt.Errorf("su3: signature verification failed for %s: %w", s.Signer, err)
		}
		return nil
	default:
		return fmt.Errorf("su3: unsupported sig type %d", s.SigType)
	}
}

// ExtractRouterInfos parses the ZIP payload of a reseed SU3 into
// RouterInfos. Reference: Reseeder (the ZIP contains routerInfo-*.dat).
func (s *SU3) ExtractRouterInfos() ([]*data.RouterInfo, error) {
	if s.FileType != SU3TypeZIP {
		return nil, fmt.Errorf("su3: unexpected file type %d", s.FileType)
	}
	zr, err := zip.NewReader(bytes.NewReader(s.Content), int64(len(s.Content)))
	if err != nil {
		return nil, fmt.Errorf("su3: zip: %w", err)
	}
	var out []*data.RouterInfo
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(f.Name, "routerInfo-") || !strings.HasSuffix(f.Name, ".dat") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if err != nil {
			continue
		}
		ri, err := data.ReadRouterInfo(content, false)
		if err != nil {
			continue
		}
		out = append(out, &ri)
	}
	return out, nil
}

// ParseCertsPEM parses a bundle of PEM certificates (the reseed signer
// certs) into a public-key map keyed by common name.
// Reference: DirKeyRing.
func ParseCertsPEM(pemBytes []byte) (map[string]crypto.PublicKey, error) {
	keys := map[string]crypto.PublicKey{}
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		keys[cert.Subject.CommonName] = cert.PublicKey
	}
	return keys, nil
}

// DefaultSeedURLs is the default reseed host list.
// Reference: Reseeder.java DEFAULT_SSL_SEED_URL.
var DefaultSeedURLs = []string{
	"https://reseed2.i2pgit.org/",
	"https://reseed.kiota.ch/",
	"https://waw01.i2p-reseed.hosted-by.skhron.eu/",
	"https://sto01.i2p-reseed.hosted-by.skhron.eu/",
	"https://i2p.ntp.poweredbyberlin.de/",
	"https://spiral.likogan.dev/",
	"https://reseed.sahil.world/",
	"https://i2p.diyarciftci.xyz/",
	"https://reseed.stormycloud.org/",
	"https://reseed-pl.i2pd.xyz/",
	"https://reseed-fr.i2pd.xyz/",
	"https://www2.mk16.de/",
	"https://reseed2.i2p.net/",
	"https://reseed.diva.exchange/",
	"https://i2p.novg.net/",
	"https://i2pseed.creativecowpat.net:8443/",
	"https://reseed.onion.im/",
}

// SU3Filename is the file reseed hosts serve.
const SU3Filename = "i2pseeds.su3"

var _ = sha256.Sum256

// verifyRSAI2P verifies an I2P raw RSA signature. Java verifies SU3
// through DSAEngine.verifySignature(sig, hash, pubKey) →
// altVerifySigRaw, which uses the JCA "NONEwithRSA" algorithm: a
// PKCS#1 v1.5 type-1 block whose contents are the bare digest bytes
// (no DigestInfo wrapper), so Go's rsa.VerifyPKCS1v15 does not apply.
// Reference: DSAEngine.java altVerifySigRaw + SigUtil.toJavaSig.
func verifyRSAI2P(pub *rsa.PublicKey, digest, sig []byte) error {
	k := pub.Size()
	if len(sig) != k {
		return fmt.Errorf("rsa: signature length %d != key size %d", len(sig), k)
	}
	m := new(big.Int).SetBytes(sig)
	if m.Cmp(pub.N) >= 0 {
		return fmt.Errorf("rsa: signature out of range")
	}
	e := big.NewInt(int64(pub.E))
	em := new(big.Int).Exp(m, e, pub.N)
	block := em.Bytes()
	// Left-pad to k (Exp strips leading zeros).
	if len(block) > k {
		return fmt.Errorf("rsa: recovered block too long")
	}
	padded := make([]byte, k)
	copy(padded[k-len(block):], block)
	// PKCS#1 v1.5 type-1: 0x00 0x01 PS(0xFF...) 0x00 || digest.
	if len(padded) < 11 {
		return fmt.Errorf("rsa: block too short")
	}
	if padded[0] != 0x00 || padded[1] != 0x01 {
		return fmt.Errorf("rsa: bad block type")
	}
	i := 2
	for i < len(padded) && padded[i] == 0xFF {
		i++
	}
	if i == len(padded) || padded[i] != 0x00 || i < 10 {
		return fmt.Errorf("rsa: bad padding")
	}
	if !bytes.Equal(padded[i+1:], digest) {
		return fmt.Errorf("rsa: digest mismatch")
	}
	return nil
}

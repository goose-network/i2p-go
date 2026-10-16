// Package ntcp2 implements the NTCP2 transport: the Noise XK
// handshake with I2P's AES-256-CBC ephemeral-key obfuscation
// ("aesobfse") and the SipHash-obfuscated-length data phase.
//
// This package mirrors the Java reference implementation files
// router/java/src/net/i2p/router/transport/ntcp/{OutboundNTCP2State,
// InboundEstablishState, NTCPConnection, NTCP2Payload, EstablishBase}.
// java in the I2P reference router (../i2p.i2p).
package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Obfuscate encrypts data in place with AES-256-CBC under key (Bob's
// router hash) and iv. NTCP2 uses this to hide the ephemeral keys in
// messages 1 and 2. Reference: OutboundNTCP2State.prepareOutbound
// (_context.aes().encrypt over the first KEY_SIZE bytes).
func Obfuscate(data, key, iv []byte) error {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("ntcp2: AES input length %d not block-aligned", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	return nil
}

// Deobfuscate decrypts data in place (the inverse of Obfuscate).
// Reference: OutboundNTCP2State.receiveOutbound (AES decrypt of Y).
func Deobfuscate(data, key, iv []byte) error {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("ntcp2: AES input length %d not block-aligned", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	return nil
}

// randBytes returns n random bytes, or panics on entropy failure
// (matching the fail-fast behavior of the transport on entropy loss).
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ntcp2: entropy failure: " + err.Error())
	}
	return b
}

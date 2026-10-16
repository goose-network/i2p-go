// Tunnel layer encryption. Every hop transforms a 1024-byte tunnel
// message with its own layer key (AES-256-CBC over bytes 16..1024,
// using the 16-byte IV at bytes 0..15) and its IV key (AES-256 applied
// directly to the IV block, before and after the layer encryption —
// the "double IV encryption").
//
// Hops ENCRYPT as a message passes through them; the tunnel endpoints
// apply the inverse per-hop transform in reverse hop order:
//
//	IBGW + participants:  encrypt
//	IBEP:                 decrypt hops [length-2 .. 0]
//	OBGW:                 pre-decrypt hops [length-1 .. 1]; hops encrypt
//	                      as the message passes, so plaintext pops out
//	                      at the OBEP.
//
// Reference: HopProcessor.java, InboundGatewayProcessor.java,
// OutboundGatewayProcessor.java, InboundEndpointProcessor.java.
package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// IVSize is the tunnel message IV length. Reference:
// HopProcessor.IV_LENGTH.
const IVSize = 16

// LayerEncrypt applies the per-hop transform: double-IV + CBC encrypt.
// block must be a full tunnel message (multiple of 16, len >= 16).
// Reference: HopProcessor.process / InboundGatewayProcessor.process.
func LayerEncrypt(block, layerKey, ivKey []byte) error {
	return layerTransform(block, layerKey, ivKey, true)
}

// LayerDecrypt applies the inverse per-hop transform. Reference:
// OutboundGatewayProcessor.decrypt (static).
func LayerDecrypt(block, layerKey, ivKey []byte) error {
	return layerTransform(block, layerKey, ivKey, false)
}

// layerTransform does the double-IV + CBC work in place. The IV block
// (bytes 0..15) is transformed with the IV key directly (ECB single
// block); the data (bytes 16..) with the layer key in CBC mode using
// the IV as it stands between the two IV steps.
func layerTransform(block, layerKey, ivKey []byte, encrypt bool) error {
	if len(block) < IVSize || len(block)%aes.BlockSize != 0 {
		return fmt.Errorf("tunnel: bad block size %d", len(block))
	}
	ivBlock, err := aes.NewCipher(ivKey)
	if err != nil {
		return err
	}
	dataBlock, err := aes.NewCipher(layerKey)
	if err != nil {
		return err
	}

	// First IV step: ECB single-block transform of the IV in place.
	iv := block[:IVSize]
	if encrypt {
		ivBlock.Encrypt(iv, iv)
	} else {
		ivBlock.Decrypt(iv, iv)
	}

	// Layer encryption over bytes 16.. in CBC mode with that IV.
	data := block[IVSize:]
	if encrypt {
		cbc := cipher.NewCBCEncrypter(dataBlock, iv)
		cbc.CryptBlocks(data, data)
	} else {
		cbc := cipher.NewCBCDecrypter(dataBlock, iv)
		cbc.CryptBlocks(data, data)
	}

	// Second IV step.
	if encrypt {
		ivBlock.Encrypt(iv, iv)
	} else {
		ivBlock.Decrypt(iv, iv)
	}
	return nil
}

// IVValidator rejects replayed tunnel messages at the endpoint. The
// key is the pair (wire IV, first 16 bytes of wire data), which is
// unique because the gateway picks a random IV per message.
// Reference: HashSetIVValidator.
type IVValidator struct {
	seen map[[IVSize]byte][IVSize]byte
}

// NewIVValidator creates an empty validator.
func NewIVValidator() *IVValidator {
	return &IVValidator{seen: make(map[[IVSize]byte][IVSize]byte)}
}

// ReceiveIV returns false if this (IV, data prefix) pair was already
// seen. Reference: InboundEndpointProcessor.retrievePreprocessedData
// (called with the wire bytes, before decryption).
func (v *IVValidator) ReceiveIV(block []byte) bool {
	var iv, data [IVSize]byte
	copy(iv[:], block[:IVSize])
	copy(data[:], block[IVSize:2*IVSize])
	if v.seen[iv] == data {
		return false
	}
	v.seen[iv] = data
	return true
}

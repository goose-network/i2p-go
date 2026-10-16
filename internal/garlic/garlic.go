// Package garlic implements the ECIES-Ratchet garlic end-to-end
// encryption protocol (proposal 144): Elligator2 ephemeral encoding,
// the NS/NSR/ES message formats, the RatchetPayload block structure,
// ratchet tag sets, and garlic cloves.
//
// The core state mirrors the Java reference files
// router/java/src/net/i2p/router/crypto/ratchet/{ECIESAEADEngine,
// RatchetSKM, RatchetTagSet, RatchetPayload, Elligator2, SplitKeys,
// NextSessionKey}.java and
// router/java/src/net/i2p/router/message/GarlicMessageBuilder.java in
// the I2P reference router (../i2p.i2p).
package garlic

// x25519Public is provided by the noise package via a small copy here
// to avoid an import cycle; see x25519.go in this package.

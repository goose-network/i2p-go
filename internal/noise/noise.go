// Package noise implements the Noise protocol framework subset I2P
// uses: the SymmetricState/HandshakeState machinery from the vendored
// Southernstorm Noise library, with the I2P HKDF flavor and the
// 8-byte-nonce ChaChaPoly cipher.
//
// This package mirrors the Java reference implementation files
// router/java/src/com/southernstorm/noise/protocol/{SymmetricState,
// HandshakeState, Pattern, NoiseInit}.java in the I2P reference router
// (../i2p.i2p).
package noise

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
)

// Token is a Noise handshake pattern token.
type Token int

// Noise handshake tokens. Reference: Pattern.java.
const (
	FlipDir Token = -(iota + 1) // terminates a message; direction changes
	E                           // write or read an ephemeral key
	S                           // write or read an encrypted static key
	EE                          // DH(local e, remote e)
	ES                          // DH(local e, remote s) if initiator, else DH(local s, remote e)
	SE                          // DH(local s, remote e) if initiator, else DH(local e, remote s)
	SS                          // DH(local s, remote s)
)

// Pattern is a message-split list of token lists.
type Pattern [][]Token

// XK is the NTCP2 pattern: -> e es, <- e ee, -> s se.
// Reference: Pattern.noise_pattern_XK.
var XK = Pattern{
	{E, ES},
	{E, EE},
	{S, SE},
}

// IK is the ECIES-Ratchet client garlic pattern: -> e es s ss,
// <- e ee se. The protocol name is "Noise_IKelg2+hs2_25519_
// ChaChaPoly_SHA256" (39 bytes > 32, so ck starts as its SHA-256).
// The first 32 bytes of the first message are an Elligator2-encoded
// ephemeral key, overwritten after writeMessage by the caller.
// Reference: NoiseInit.PatternID.IK.
var IK = Pattern{
	{E, ES, S, SS},
	{E, EE, SE},
}

// N is the short tunnel build record pattern: -> e es, with no
// response. The protocol name is "Noise_N_25519_ChaChaPoly_SHA256".
// The initiator has no static key; the responder's static key is
// the hop's ratchet key. Reference: NoiseInit.PatternID.N and
// BuildRequestRecord.encryptECIESRecord.
var N = Pattern{
	{E, ES},
}

// NNoResponse is the anonymous netdb garlic pattern ("N!"), identical
// to N. The I2P code uses a separate enum value so the caller knows
// no post-mixHash is needed, but the token sequence is the same.
// Reference: NoiseInit.PatternID.N_NO_RESPONSE.
var NNoResponse = Pattern{
	{E, ES},
}

// SymmetricState holds the Noise chaining key ck, the handshake hash h,
// and the current message cipher.
// Reference: SymmetricState.java.
type SymmetricState struct {
	ck [32]byte
	h  [32]byte
	// cipher is nil until the first mixKey (no key yet: encryptAndHash
	// copies plaintext through).
	cipher *i2pcrypto.AEAD
}

// NewSymmetricState initializes the state from the protocol name:
// ck = protocol name zero-padded to 32, h = SHA256(ck).
// Reference: NoiseInit.PatternID ctor + SymmetricState ctor.
func NewSymmetricState(protocolName string) *SymmetricState {
	s := &SymmetricState{}
	name := []byte(protocolName)
	if len(name) > 32 {
		s.ck = sha256.Sum256(name)
	} else {
		copy(s.ck[:], name)
	}
	s.h = sha256.Sum256(s.ck[:])
	return s
}

// MixHash sets h = SHA256(h || data). Reference: SymmetricState.mixHash
// / i2pd NoiseSymmetricState::MixHash.
func (s *SymmetricState) MixHash(data []byte) {
	d := sha256.New()
	d.Write(s.h[:])
	d.Write(data)
	s.h = [32]byte(d.Sum(nil))
}

// MixKey sets ck, k = HKDF2(salt=ck, IKM=data, info="") and keys the
// message cipher with k. Reference: SymmetricState.mixKey (with the I2P
// HKDF two-output calculate).
func (s *SymmetricState) MixKey(data []byte) {
	ck, k := i2pcrypto.HKDF2(s.ck[:], data, "")
	s.ck = [32]byte(ck)
	s.cipher = i2pcrypto.NewAEAD(k)
}

// EncryptAndHash encrypts plaintext with h as AD and mixes the
// ciphertext into h. Reference: SymmetricState.encryptAndHash.
func (s *SymmetricState) EncryptAndHash(plaintext []byte) []byte {
	if s.cipher == nil {
		out := append([]byte(nil), plaintext...)
		s.MixHash(out)
		return out
	}
	ct := s.cipher.Seal(s.h[:], plaintext)
	s.MixHash(ct)
	return ct
}

// DecryptAndHash decrypts ciphertext (AD = the pre-mix h) and mixes the
// ciphertext into h. The hash updates even on failure, matching the
// Java reference. Reference: SymmetricState.decryptAndHash.
func (s *SymmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.cipher == nil {
		s.MixHash(ciphertext)
		return append([]byte(nil), ciphertext...), nil
	}
	ad := append([]byte(nil), s.h[:]...)
	s.MixHash(ciphertext)
	return s.cipher.Open(ad, ciphertext)
}

// Split returns the transport keys k1 (initiator->responder) and k2
// (responder->initiator). Reference: SymmetricState.split.
func (s *SymmetricState) Split() (k1, k2 []byte) {
	return i2pcrypto.HKDF2(s.ck[:], nil, "")
}

// ChainingKey returns a copy of the chaining key (I2P extension used
// by the NTCP2 SipHash KDF). Reference: HandshakeState.getChainingKey.
func (s *SymmetricState) ChainingKey() []byte {
	return append([]byte(nil), s.ck[:]...)
}

// HandshakeHash returns a copy of h. Reference:
// SymmetricState.getHandshakeHash.
func (s *SymmetricState) HandshakeHash() []byte {
	return append([]byte(nil), s.h[:]...)
}

// clone deep-copies the symmetric state. The message cipher's nonce
// counter must be preserved: the handshake payload of each message is
// encrypted with the cipher at its current counter, and a cloned
// state (e.g. a stored post-msg1 state processing an NSR) must use
// the same counter as the side that advanced it.
func (s *SymmetricState) clone() *SymmetricState {
	c := &SymmetricState{ck: s.ck, h: s.h}
	if s.cipher != nil {
		c.cipher = i2pcrypto.NewAEAD(s.cipher.Key())
		c.cipher.SetNonce(s.cipher.Nonce())
	}
	return c
}

// HandshakeState executes a Noise handshake. Reference: HandshakeState.java.
type HandshakeState struct {
	symmetric *SymmetricState
	pattern   Pattern
	msgIndex  int
	// role. Initiator writes messages 0, 2, ...; responder 1, 3, ...
	initiator bool
	// action: 0 = write, 1 = read, 2 = split, 3 = complete/failed.
	action int

	localStaticPriv, localStaticPub []byte // s
	localEphemPriv, localEphemPub   []byte // e
	// ephReady: a caller-provided ephemeral (GenerateEphemeralPair)
	// is waiting to be written into the next message's E token.
	// WriteMessage clears it after use so subsequent messages get
	// fresh keys. Reference: Java passes an Elligator2 key factory to
	// the HandshakeState ctor for the same effect.
	ephReady     bool
	remoteStatic []byte // rs (Bob's s, known to Alice for XK)
	remoteEphem  []byte // re
	// started records whether Start's pre-message hashing ran, so a
	// double Start is harmless (Java throws; we tolerate).
	started bool
}

// NewHandshakeState creates a handshake for pattern (XK or IK), with
// the local static keypair and, for the initiator, the remote static
// key. A nil localStaticPriv generates a fresh keypair.
// Reference: HandshakeState ctor.
func NewHandshakeState(protocolName string, pattern Pattern, initiator bool, localStaticPriv []byte, remoteStatic []byte) (*HandshakeState, error) {
	if len(remoteStatic) != 0 && len(remoteStatic) != 32 {
		return nil, fmt.Errorf("noise: bad remote static length %d", len(remoteStatic))
	}
	h := &HandshakeState{
		symmetric:    NewSymmetricState(protocolName),
		pattern:      pattern,
		initiator:    initiator,
		action:       0,
		remoteStatic: append([]byte(nil), remoteStatic...),
	}
	if len(localStaticPriv) == 0 {
		h.localStaticPriv = make([]byte, 32)
		if _, err := rand.Read(h.localStaticPriv); err != nil {
			return nil, err
		}
	} else {
		if len(localStaticPriv) != 32 {
			return nil, fmt.Errorf("noise: bad static priv length %d", len(localStaticPriv))
		}
		h.localStaticPriv = append([]byte(nil), localStaticPriv...)
	}
	// Derive the static public key now so RouterInfo publishing and
	// msg3 construction can use it before the handshake starts.
	var err error
	h.localStaticPub, err = x25519Public(h.localStaticPriv)
	if err != nil {
		return nil, err
	}
	if initiator {
		// Alice writes the first message.
		h.action = 0
	} else {
		// Bob reads the first message.
		h.action = 1
	}
	h.Start()
	return h, nil
}

// Start finalizes the handshake setup: the pre-message static key is
// hashed into h (the "<- s" pre-message every pattern we implement
// carries — XK, IK, and N). Without this the AEAD associated data
// diverges from the reference routers' and every handshake fails
// verification. Reference: HandshakeState.start() (LOCAL_PREMSG /
// REMOTE_PREMSG) and i2pd InitNoiseState (h = SHA256(hh || pub)).
func (h *HandshakeState) Start() {
	if h.started {
		return
	}
	h.started = true
	// The pre-message key is the responder's static key: the initiator
	// knows it as the remote static, the responder owns it locally.
	if h.initiator {
		if len(h.remoteStatic) == 32 {
			h.symmetric.MixHash(h.remoteStatic)
		}
	} else if len(h.localStaticPub) == 32 {
		h.symmetric.MixHash(h.localStaticPub)
	}
}

// LocalStaticPublic returns the local static public key.
func (h *HandshakeState) LocalStaticPublic() []byte {
	return append([]byte(nil), h.localStaticPub...)
}

// LocalStaticPrivate returns the local static private key.
func (h *HandshakeState) LocalStaticPrivate() []byte {
	return append([]byte(nil), h.localStaticPriv...)
}

// RemoteStatic returns the remote static public key (valid after the S
// token is read, or immediately for the initiator in XK).
func (h *HandshakeState) RemoteStatic() []byte {
	return append([]byte(nil), h.remoteStatic...)
}

// RemoteEphemeral returns the remote ephemeral public key.
func (h *HandshakeState) RemoteEphemeral() []byte {
	return append([]byte(nil), h.remoteEphem...)
}

// LocalEphemeral returns the local ephemeral public key (after the E
// token of a written message, or msg1's key for the responder).
func (h *HandshakeState) LocalEphemeral() []byte {
	return append([]byte(nil), h.localEphemPub...)
}

// GenerateEphemeralPair generates the ephemeral keypair used for the
// next message. The next written E token will use this pair instead of
// generating a fresh one, so callers can pre-select properties (e.g.
// Elligator2 encodability). Reference: HandshakeState E-token handling.
func (h *HandshakeState) GenerateEphemeralPair() error {
	h.localEphemPriv = make([]byte, 32)
	if _, err := rand.Read(h.localEphemPriv); err != nil {
		return err
	}
	pub, err := x25519Public(h.localEphemPriv)
	if err != nil {
		return err
	}
	h.localEphemPub = pub
	h.ephReady = true
	return nil
}

// SetEphemeralPair installs a caller-supplied ephemeral keypair for the
// next written E token (used to guarantee an Elligator2-encodable key).
func (h *HandshakeState) SetEphemeralPair(priv, pub []byte) {
	h.localEphemPriv = append([]byte(nil), priv...)
	h.localEphemPub = append([]byte(nil), pub...)
	h.ephReady = true
}

// Clone deep-copies the handshake state (the stored post-msg1 state is
// cloned per NSR tag hit). Reference: HandshakeState.clone.
func (h *HandshakeState) Clone() (*HandshakeState, error) {
	c := &HandshakeState{
		symmetric: h.symmetric.clone(),
		pattern:   h.pattern,
		msgIndex:  h.msgIndex,
		initiator: h.initiator,
		action:    h.action,
		ephReady:  h.ephReady,
		started:   h.started,
	}
	if h.localStaticPriv != nil {
		c.localStaticPriv = append([]byte(nil), h.localStaticPriv...)
		c.localStaticPub = append([]byte(nil), h.localStaticPub...)
	}
	if h.localEphemPriv != nil {
		c.localEphemPriv = append([]byte(nil), h.localEphemPriv...)
		c.localEphemPub = append([]byte(nil), h.localEphemPub...)
	}
	if h.remoteStatic != nil {
		c.remoteStatic = append([]byte(nil), h.remoteStatic...)
	}
	if h.remoteEphem != nil {
		c.remoteEphem = append([]byte(nil), h.remoteEphem...)
	}
	return c, nil
}

// Action returns the current action: "write", "read", or "split".
func (h *HandshakeState) Action() string {
	switch h.action {
	case 0:
		return "write"
	case 1:
		return "read"
	case 2:
		return "split"
	default:
		return "complete"
	}
}

// WriteMessage processes the tokens for the message Alice/Bob is
// sending and appends the encrypted payload. Returns the full message
// bytes. Reference: HandshakeState.writeMessage.
func (h *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if h.action != 0 {
		return nil, fmt.Errorf("noise: state %s does not allow writing", h.Action())
	}
	if h.msgIndex >= len(h.pattern) {
		h.action = 2
		return nil, nil
	}
	var out []byte
	for _, tok := range h.pattern[h.msgIndex] {
		switch tok {
		case E:
			if !h.ephReady {
				if err := h.GenerateEphemeralPair(); err != nil {
					return nil, err
				}
			}
			h.ephReady = false
			out = append(out, h.localEphemPub...)
			h.symmetric.MixHash(h.localEphemPub)
		case S:
			// Encrypt the local static key with the current h.
			out = append(out, h.symmetric.EncryptAndHash(h.localStaticPub)...)
		case EE:
			shared, err := x25519DH(h.localEphemPriv, h.remoteEphem)
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case ES:
			var shared []byte
			var err error
			if h.initiator {
				shared, err = x25519DH(h.localEphemPriv, h.remoteStatic)
			} else {
				shared, err = x25519DH(h.localStaticPriv, h.remoteEphem)
			}
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case SE:
			var shared []byte
			var err error
			if h.initiator {
				shared, err = x25519DH(h.localStaticPriv, h.remoteEphem)
			} else {
				shared, err = x25519DH(h.localEphemPriv, h.remoteStatic)
			}
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case SS:
			shared, err := x25519DH(h.localStaticPriv, h.remoteStatic)
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		}
	}
	// Payload.
	out = append(out, h.symmetric.EncryptAndHash(payload)...)
	h.msgIndex++
	if h.msgIndex >= len(h.pattern) {
		h.action = 2 // split next
	} else {
		h.action = 1 // read next
	}
	return out, nil
}

// ReadMessage processes a message from the peer. payload receives the
// decrypted message payload. Returns the payload.
// Reference: HandshakeState.readMessage.
func (h *HandshakeState) ReadMessage(message []byte) ([]byte, error) {
	if h.action != 1 {
		return nil, fmt.Errorf("noise: state %s does not allow reading", h.Action())
	}
	var payload []byte
	var err error
	if h.msgIndex >= len(h.pattern) {
		h.action = 2
		return nil, nil
	}
	off := 0
	for _, tok := range h.pattern[h.msgIndex] {
		switch tok {
		case E:
			if len(message)-off < 32 {
				return nil, errors.New("noise: short message for E token")
			}
			h.remoteEphem = append([]byte(nil), message[off:off+32]...)
			h.symmetric.MixHash(h.remoteEphem)
			if allZero(h.remoteEphem) {
				return nil, errors.New("noise: null remote ephemeral key")
			}
			off += 32
		case S:
			if len(message)-off < 48 {
				return nil, errors.New("noise: short message for S token")
			}
			pt, err := h.symmetric.DecryptAndHash(message[off : off+48])
			if err != nil {
				return nil, err
			}
			h.remoteStatic = append([]byte(nil), pt...)
			off += 48
		case EE:
			shared, err := x25519DH(h.localEphemPriv, h.remoteEphem)
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case ES:
			var shared []byte
			var err error
			if h.initiator {
				shared, err = x25519DH(h.localEphemPriv, h.remoteStatic)
			} else {
				shared, err = x25519DH(h.localStaticPriv, h.remoteEphem)
			}
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case SE:
			var shared []byte
			var err error
			if h.initiator {
				shared, err = x25519DH(h.localStaticPriv, h.remoteEphem)
			} else {
				shared, err = x25519DH(h.localEphemPriv, h.remoteStatic)
			}
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		case SS:
			shared, err := x25519DH(h.localStaticPriv, h.remoteStatic)
			if err != nil {
				return nil, err
			}
			h.symmetric.MixKey(shared)
		}
	}
	payload, err = h.symmetric.DecryptAndHash(message[off:])
	if err != nil {
		return nil, err
	}
	h.msgIndex++
	if h.msgIndex >= len(h.pattern) {
		h.action = 2
	} else {
		h.action = 0
	}
	return payload, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Split finishes the handshake and returns the transport cipher pair:
// the sender and receiver cipher states for this role.
// Reference: HandshakeState.split (responder's pair is swapped).
func (h *HandshakeState) Split() (send, recv *i2pcrypto.AEAD, err error) {
	if h.action != 2 {
		return nil, nil, fmt.Errorf("noise: state %s does not allow split", h.Action())
	}
	k1, k2 := h.symmetric.Split()
	send = i2pcrypto.NewAEAD(k1)
	recv = i2pcrypto.NewAEAD(k2)
	if !h.initiator {
		send, recv = recv, send
	}
	h.action = 3
	return send, recv, nil
}

// ChainingKey returns the post-split chaining key (for the NTCP2
// SipHash KDF). Reference: HandshakeState.getChainingKey.
func (h *HandshakeState) ChainingKey() []byte { return h.symmetric.ChainingKey() }

// MixHash mixes data into the handshake hash (the NTCP2 padding
// extension). Reference: OutboundNTCP2State padding mixHash calls.
func (h *HandshakeState) MixHash(data []byte) { h.symmetric.MixHash(data) }

// HandshakeHash returns the final handshake hash.
func (h *HandshakeState) HandshakeHash() []byte { return h.symmetric.HandshakeHash() }

// The ECIES-Ratchet encrypt/decrypt engine: New Session (NS), New
// Session Reply (NSR), and Existing Session (ES) messages, plus the
// one-time session wrapper used for netdb replies and outbound tunnel
// build reply messages.
//
// Wire formats (proposal 144, ECIESAEADEngine.java):
//
//	NS  (Alice→Bob): [32 elg2 eph][48 enc static][payload ct][16 mac]
//	NSR (Bob→Alice): [8 tag][32 elg2 eph][16 mac (msg2, empty payload)]
//	                  [payload ct][16 mac (part-2 key)]
//	ES  (either):    [8 tag][payload ct][16 mac], AD = tag, nonce = key n
package garlic

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
	"github.com/goose-network/i2p-go/internal/noise"
)

// Protocol name for the IK pattern. 39 chars > 32 so ck = SHA256(name).
const protocolNameIK = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"

// nullPK is the all-zeros static key used for anonymous (N-in-IK)
// sessions. Reference: ECIESAEADEngine.NULLPK.
var nullPK = make([]byte, 32)

// minNSAge / maxNSFuture bound the DateTime block clock skew.
const (
	minNSAge    = 90 * time.Minute
	maxNSFuture = 90 * time.Minute
)

// Manager owns all ratchet sessions for one key pair (one side of the
// protocol): the local ratchet private key, sessions by remote public
// key, and one-time tags.
type Manager struct {
	priv []byte // our ratchet private key
	pub  []byte // our ratchet public key

	mu       sync.Mutex
	sessions map[string]*Session // by remote public key
	oneTime  map[string]*oneTimeEntry
}

type oneTimeEntry struct {
	key      []byte
	expireAt time.Time
}

// NewManager creates a manager for our ratchet key pair.
func NewManager(priv []byte) (*Manager, error) {
	pub, err := x25519Public(priv)
	if err != nil {
		return nil, err
	}
	return &Manager{
		priv:     append([]byte(nil), priv...),
		pub:      pub,
		sessions: map[string]*Session{},
		oneTime:  map[string]*oneTimeEntry{},
	}, nil
}

// PublicKey returns our ratchet public key.
func (m *Manager) PublicKey() []byte { return m.pub }

// OneTimeSession is a single key/tag pair for one ES message.
// Reference: MessageWrapper.OneTimeSession.
type OneTimeSession struct {
	Key []byte
	Tag []byte // 8-byte RatchetSessionTag
}

// GenerateOneTimeSession creates a one-time session and registers the
// tag for inbound decryption. Reference: MessageWrapper.generateSession
// (ratchet branch).
func (m *Manager) GenerateOneTimeSession(expiration time.Duration) *OneTimeSession {
	key := make([]byte, 32)
	tag := make([]byte, 8)
	if err := readRandom(key); err != nil {
		return nil
	}
	if err := readRandom(tag); err != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.oneTime[string(tag)] = &oneTimeEntry{key: key, expireAt: time.Now().Add(expiration)}
	return &OneTimeSession{Key: key, Tag: tag}
}

// EncryptOneTime wraps cloves in a one-time ES message: n=0, AD=tag,
// cloves + padding only (no DateTime/NextKey/Ack blocks).
// Reference: ECIESAEADEngine.encrypt(cloves, key, tag).
func EncryptOneTime(cloves []*Clove, sess *OneTimeSession) []byte {
	payload := buildPayload(cloves, time.Time{}, false, nil, nil, ESOverhead)
	return encryptAEAD(sess.Tag, payload, sess.Key, 0)
}

// encryptAEAD encrypts with ChaChaPoly, 8-byte-nonce layout, prefixing
// the AD (the ES tag) to the ciphertext.
// Reference: ECIESAEADEngine.encryptAEADBlock.
func encryptAEAD(ad, data, key []byte, n uint64) []byte {
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(n)
	return append(append([]byte(nil), ad...), a.Seal(ad, data)...)
}

// decryptAEAD is the inverse of encryptAEAD. data includes the AD
// prefix (tag), stripped from the returned plaintext.
func decryptAEAD(data, key []byte, n uint64, adLen int) ([]byte, error) {
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(n)
	return a.Open(data[:adLen], data[adLen:])
}

// sealAEAD encrypts with AD that is not part of the wire format (the
// NSR part-2 AD is the out-of-band handshake hash).
func sealAEAD(ad, data, key []byte, n uint64) []byte {
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(n)
	return a.Seal(ad, data)
}

// openAEAD is the inverse of sealAEAD.
func openAEAD(ad, data, key []byte, n uint64) ([]byte, error) {
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(n)
	return a.Open(ad, data)
}

// EncryptSession encrypts cloves to the target using the best
// available session state: ES if a tag remains, else a new NS.
// Reference: ECIESAEADEngine.encrypt.
func (m *Manager) EncryptSession(target []byte, cloves []*Clove) []byte {
	m.mu.Lock()
	sess := m.sessions[string(target)]
	m.mu.Unlock()
	if sess != nil {
		if entry := sess.consumeNext(); entry != nil {
			return m.encryptES(cloves, entry)
		}
	}
	// No session (or exhausted): New Session. We are Alice; the
	// handshake state is stored to match the NSR.
	ns, err := m.buildNS(target, cloves)
	if err != nil {
		return nil
	}
	return ns
}

// encryptES builds an ES message from a consumed entry.
// Reference: ECIESAEADEngine.encryptExistingSession.
func (m *Manager) encryptES(cloves []*Clove, entry *RatchetEntry) []byte {
	payload := buildPayload(cloves, time.Time{}, false,
		joinKeys(entry.NextFwd, entry.NextRev), nil, ESOverhead)
	return encryptAEAD(entry.Tag, payload, entry.Key, uint64(entry.Nonce))
}

// joinKeys flattens the optional fwd/rev announcements for
// buildPayload.
func joinKeys(fwd, rev *NextSessionKey) []NextSessionKey {
	var out []NextSessionKey
	if fwd != nil {
		out = append(out, *fwd)
	}
	if rev != nil {
		out = append(out, *rev)
	}
	return out
}

// buildNS creates the NS message 1 (IK first flight).
// Reference: ECIESAEADEngine.encryptNewSession (with priv).
func (m *Manager) buildNS(target []byte, cloves []*Clove) ([]byte, error) {
	state, err := noise.NewHandshakeState(protocolNameIK, noise.IK, true, m.priv, target)
	if err != nil {
		return nil, err
	}
	// The ephemeral must be Elligator2-encodable: generate an encodable
	// pair and install it for the E token (the Java code passes an
	// Elligator2 key factory to the HandshakeState).
	priv, _, encoded, err := GenerateElligator2Keypair()
	if err != nil {
		return nil, err
	}
	pub, err := x25519Public(priv)
	if err != nil {
		return nil, err
	}
	state.SetEphemeralPair(priv, pub)
	payload := buildPayload(cloves, time.Now(), false, nil, nil, NSOverhead)
	msg, err := state.WriteMessage(payload)
	if err != nil {
		return nil, err
	}
	// Overwrite the ephemeral with its Elligator2 encoding.
	copy(msg, encoded)
	// Store the state for NSR matching.
	m.mu.Lock()
	m.sessions[string(target)] = newAliceSession(target, state, time.Now())
	m.mu.Unlock()
	return msg, nil
}

// DecryptMessage decrypts an NS, NSR, or ES message addressed to our
// ratchet key (or a one-time tag). Returns the cloves.
// Reference: ECIESAEADEngine.decrypt.
func (m *Manager) DecryptMessage(data []byte) ([]*Clove, error) {
	if len(data) < 8+16 {
		return nil, fmt.Errorf("garlic: short message %d", len(data))
	}
	tag := data[:8]
	// One-time tag?
	m.mu.Lock()
	ot := m.oneTime[string(tag)]
	if ot != nil {
		delete(m.oneTime, string(tag))
	}
	m.mu.Unlock()
	if ot != nil {
		if time.Now().After(ot.expireAt) {
			return nil, fmt.Errorf("garlic: expired one-time tag")
		}
		pt, err := decryptAEAD(data, ot.key, 0, 8)
		if err != nil {
			return nil, err
		}
		pp, err := ProcessPayload(pt, false)
		if err != nil {
			return nil, err
		}
		return pp.Cloves, nil
	}
	// Ratchet tag set?
	m.mu.Lock()
	var sessions []*Session
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		cloves, handled, err := s.decrypt(m, data)
		if handled {
			return cloves, err
		}
	}
	// New Session (no tag): IK msg1.
	return m.decryptNS(data)
}

// decrypt tries one session's inbound tag sets.
func (s *Session) decrypt(m *Manager, data []byte) ([]*Clove, bool, error) {
	tag := data[:8]
	var nextKeys []NextSessionKey
	s.mu.Lock()
	// NSR tagsets first (Alice).
	for _, ts := range s.nsrTagSets {
		if tk := ts.consume(tag); tk != nil {
			// NSR: clone the stored state, process msg2 with the clone.
			// (The stored state stays usable for the other pending tags.)
			state, err := tk.State.Clone()
			if err != nil {
				s.mu.Unlock()
				return nil, true, err
			}
			cloves, err := decryptNSR(state, data)
			if err != nil {
				s.mu.Unlock()
				return nil, true, err
			}
			s.updateToES(state, time.Now())
			s.mu.Unlock()
			return cloves, true, nil
		}
	}
	// ES inbound.
	if s.inES != nil {
		if tk := s.inES.consume(tag); tk != nil {
			pt, err := decryptAEAD(data, tk.Key, uint64(tk.Nonce), 8)
			if err != nil {
				s.mu.Unlock()
				return nil, true, err
			}
			pp, err := ProcessPayload(pt, false)
			if err != nil {
				s.mu.Unlock()
				return nil, true, err
			}
			// nextKeyReceived re-locks s.mu, so it must run after the
			// unlock; collect the keys here.
			nextKeys = pp.NextKeys
			s.mu.Unlock()
			for _, nk := range nextKeys {
				if err := s.nextKeyReceived(nk); err != nil {
					// log and continue
					_ = err
				}
			}
			return pp.Cloves, true, nil
		}
	}
	s.mu.Unlock()
	return nil, false, nil
}

// decryptNS processes an inbound NS (we are Bob).
// Reference: ECIESAEADEngine.decryptNewSession.
func (m *Manager) decryptNS(data []byte) ([]*Clove, error) {
	if len(data) < 96+7 {
		return nil, fmt.Errorf("garlic: short NS %d", len(data))
	}
	// Elg2 decode the ephemeral.
	pk := Elligator2Decode(data[:32])
	if pk == nil {
		return nil, fmt.Errorf("garlic: elg2 decode fail NS")
	}
	if pk[31]&0x80 != 0 {
		return nil, fmt.Errorf("garlic: bad PK decode fail NS")
	}
	buf := append([]byte(nil), data...)
	copy(buf, pk)
	state, err := noise.NewHandshakeState(protocolNameIK, noise.IK, false, m.priv, nil)
	if err != nil {
		return nil, err
	}
	payload, err := state.ReadMessage(buf)
	if err != nil {
		return nil, err
	}
	pp, err := ProcessPayload(payload, true)
	if err != nil {
		return nil, err
	}
	if pp.DateTime == 0 {
		return nil, fmt.Errorf("garlic: no datetime block in NS")
	}
	now := time.Now()
	if time.Duration(now.UnixMilli()-pp.DateTime)*time.Millisecond < -minNSAge ||
		time.Duration(pp.DateTime-now.UnixMilli())*time.Millisecond > maxNSFuture {
		return nil, fmt.Errorf("garlic: clock skew in NS")
	}
	remote := state.RemoteStatic()
	if !bytes.Equal(remote, nullPK) {
		// Record the session for the NSR we will send.
		m.mu.Lock()
		m.sessions[string(remote)] = newBobSession(remote, state, time.Now())
		m.mu.Unlock()
	} else {
		return nil, fmt.Errorf("garlic: anonymous NS to ratchet manager")
	}
	return pp.Cloves, nil
}

// BuildNSR creates the NSR (Bob → Alice) after receiving an NS.
// Reference: ECIESAEADEngine.encryptNewSessionReply.
func (m *Manager) BuildNSR(state *noise.HandshakeState, cloves []*Clove) []byte {
	m.mu.Lock()
	sess := m.sessions[string(state.RemoteStatic())]
	m.mu.Unlock()
	if sess == nil {
		return nil
	}
	sess.mu.Lock()
	ts := sess.outNSR
	sess.mu.Unlock()
	if ts == nil {
		return nil
	}
	ts.mu.Lock()
	tag := ts.consumeNext()
	ts.mu.Unlock()
	if tag == nil {
		return nil
	}
	tag = tag[:tagLen]
	// mixHash(tag) into the state.
	state.MixHash(tag)
	payload := buildPayload(cloves, time.Time{}, false, nil, nil, NSROverhead)

	// The msg2 ephemeral must be Elligator2-encodable.
	priv, _, encoded, err := GenerateElligator2Keypair()
	if err != nil {
		return nil
	}
	pub, err := x25519Public(priv)
	if err != nil {
		return nil
	}
	state.SetEphemeralPair(priv, pub)

	// part 1 — tag + msg2 with empty payload.
	enc := make([]byte, 0, 72+len(payload))
	enc = append(enc, tag...)
	msg2, err := state.WriteMessage(nil)
	if err != nil {
		return nil
	}
	enc = append(enc, msg2...)
	// overwrite eph with elg2 encoding
	copy(enc[len(tag):len(tag)+32], encoded)

	// split
	sp := noiseSplit(state)
	// part 2 — payload encrypted with k_ba-derived key, AD = handshake
	// hash, n=0.
	encpayloadkey := i2pcrypto.HKDF(sp.Kba, nil, infoAttachPayloadKDF)
	ct := sealAEAD(state.HandshakeHash(), payload, encpayloadkey, 0)
	enc = append(enc, ct...)
	// Session transitions to ES; the state is the one we just updated.
	sess.updateToES(state, time.Now())
	return enc
}

// decryptNSR processes an inbound NSR (we are Alice). The state is the
// stored post-msg1 state (consumed from the tag set).
// Reference: ECIESAEADEngine.decryptNewSessionReply.
func decryptNSR(state *noise.HandshakeState, data []byte) ([]*Clove, error) {
	if len(data) < 72 {
		return nil, fmt.Errorf("garlic: short NSR %d", len(data))
	}
	yy := data[8:40]
	pk := Elligator2Decode(yy)
	if pk == nil {
		return nil, fmt.Errorf("garlic: elg2 decode fail NSR")
	}
	buf := append([]byte(nil), data...)
	copy(buf[8:40], pk)
	state.MixHash(data[:8])
	// part 1: msg2 (48 bytes: 32 eph + 16 mac), empty payload.
	if _, err := state.ReadMessage(buf[8 : 8+48]); err != nil {
		return nil, err
	}
	sp := noiseSplit(state)
	// part 2: key = HKDF(k_ba, "", "AttachPayloadKDF"), AD = handshake
	// hash, n=0. Part 1 is TAGLEN+KEYLEN+MACLEN = 56 bytes on the wire
	// (the tag is not re-counted; msg2 is 32 eph + 16 MAC with an empty
	// payload). Reference: decryptNewSessionReply.
	encpayloadkey := i2pcrypto.HKDF(sp.Kba, nil, infoAttachPayloadKDF)
	pt, err := openAEAD(state.HandshakeHash(), buf[56:], encpayloadkey, 0)
	if err != nil {
		return nil, err
	}
	if len(pt) == 0 {
		return []*Clove{}, nil
	}
	pp, err := ProcessPayload(pt, false)
	if err != nil {
		return nil, err
	}
	return pp.Cloves, nil
}

// EncryptToTargetNS encrypts cloves in an anonymous N message (used
// for netdb lookups when we have no session). Reference:
// ECIESAEADEngine.encryptNewSession (N pattern, no static).
func EncryptToTargetNS(target []byte, cloves []*Clove) []byte {
	state, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, true, nil, target)
	if err != nil {
		return nil
	}
	payload := buildPayload(cloves, time.Now(), false, nil, nil, NSNOverhead)
	msg, err := state.WriteMessage(payload)
	if err != nil {
		return nil
	}
	return msg
}

// protocolNameN is the anonymous N pattern name.
const protocolNameN = "Noise_N_25519_ChaChaPoly_SHA256"

// NSNOverhead is the N-pattern message overhead (32 eph + 16 mac).
const NSNOverhead = 48

// readRandom fills b. (Small helper to keep imports tidy.)
func readRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// DecryptNSAnonymous decrypts an anonymous N message addressed to our
// key (no session state). Reference: ECIESAEADEngine.decryptNewSession
// (N branch).
func (m *Manager) DecryptNSAnonymous(data []byte) ([]*Clove, error) {
	state, err := noise.NewHandshakeState(protocolNameN, noise.NNoResponse, false, m.priv, nil)
	if err != nil {
		return nil, err
	}
	payload, err := state.ReadMessage(data)
	if err != nil {
		return nil, err
	}
	pp, err := ProcessPayload(payload, true)
	if err != nil {
		return nil, err
	}
	if pp.DateTime == 0 {
		return nil, fmt.Errorf("garlic: no datetime in N")
	}
	return pp.Cloves, nil
}

// checkClovesExpiration is a helper for receivers that verify the
// DateTime block freshness (used by tests).
func checkClovesExpiration(pp *ParsedPayload, now time.Time) error {
	if pp.DateTime == 0 {
		return fmt.Errorf("garlic: no datetime")
	}
	dt := time.UnixMilli(pp.DateTime)
	if dt.Before(now.Add(-minNSAge)) || dt.After(now.Add(maxNSFuture)) {
		return fmt.Errorf("garlic: clock skew")
	}
	return nil
}

// secureEqual is a constant-time comparison helper.
func secureEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

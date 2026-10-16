// RatchetTagSet and the NS/NSR/ES session state machine for
// ECIES-Ratchet garlic. A tag set is one direction of a session: an
// ordered chain of 8-byte session tags (from the sesstag chain) paired
// with 32-byte keys (from the symmkey chain). Inbound tag sets pre-
// generate tags for the listener; outbound tag sets generate lazily.
//
// This file ports RatchetTagSet.java, SessionKeyAndNonce.java,
// RatchetEntry.java, and the OutboundSession state machine from
// RatchetSKM.java.
package garlic

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
	"github.com/goose-network/i2p-go/internal/noise"
)

// Tagset KDF info strings. Reference: RatchetTagSet.java INFO_1-5,
// RatchetSKM OutboundSession INFO_0/7, ECIESAEADEngine INFO_6.
const (
	infoKDFDHRatchetStep = "KDFDHRatchetStep"
	infoTagAndKeyGenKeys = "TagAndKeyGenKeys"
	infoSTInitialization = "STInitialization"
	infoSessionTagKeyGen = "SessionTagKeyGen"
	infoSymmetricRatchet = "SymmetricRatchet"
	infoSessionReplyTags = "SessionReplyTags"
	infoXDHRatchetTagSet = "XDHRatchetTagSet"
	infoAttachPayloadKDF = "AttachPayloadKDF"
	tagSetMax            = 65535
	minRcvWindowNSR      = 12
	maxRcvWindowNSR      = 12
	minRcvWindowES       = 24
	maxRcvWindowES       = 320
	tagLen               = 8
	// low is when an outbound ES tagset starts advertising a next key
	// (4 * max streaming window). Reference: RatchetTagSet.LOW.
	lowTagRemaining = tagSetMax - 4096
)

// TagAndKey is one tag/key/nonce triple for an ES message.
// Reference: SessionKeyAndNonce.
type TagAndKey struct {
	Tag   []byte // 8 bytes
	Key   []byte // 32 bytes
	Nonce int    // for inbound ES: the tag number
	// State is non-nil for NSR replies: the message is decrypted with
	// the cloned HandshakeState, not a symmetric key.
	State *noise.HandshakeState
}

// RatchetTagSet is one direction of a ratchet session.
// Reference: RatchetTagSet.
type RatchetTagSet struct {
	ID           int
	KeyID        int
	rootKey      []byte
	nextRootKey  []byte
	sesstagCK    []byte
	sesstagConst []byte
	symmkeyCK    []byte
	lastTag      int
	lastKey      int
	isInbound    bool
	// state is the post-msg1 HandshakeState for NSR tag sets (the
	// inbound side stores it; a tag hit means "this is an NSR").
	state *noise.HandshakeState

	mu        sync.Mutex
	tags      map[int][]byte // inbound: tagnum -> tag
	keys      map[int][]byte // inbound ES: tagnum -> key
	minSize   int
	maxSize   int
	nextKeys  *X25519KeyPair // our next forward keys (outbound)
	nextKey   *NextSessionKey
	remoteKey []byte
	acked     bool
}

// X25519KeyPair is a generated ratchet key pair.
type X25519KeyPair struct {
	Priv []byte
	Pub  []byte
}

// newRatchetTagSet runs the tagset KDF chain:
//
//	nextRootKey, ck = HKDF(rootKey, data, "KDFDHRatchetStep")
//	sesstag_ck, symmkey_ck = HKDF(ck, "", "TagAndKeyGenKeys")
//	sesstag_ck, sesstag_const = HKDF(sesstag_ck, "", "STInitialization")
//	symmkey_const = "" (empty)
//
// Reference: RatchetTagSet ctor.
func newRatchetTagSet(rootKey, data []byte, id, keyID int, isInbound bool,
	state *noise.HandshakeState, minSize, maxSize int) *RatchetTagSet {
	ts := &RatchetTagSet{
		ID:        id,
		KeyID:     keyID,
		rootKey:   append([]byte(nil), rootKey...),
		isInbound: isInbound,
		state:     state,
		minSize:   minSize,
		maxSize:   maxSize,
		tags:      map[int][]byte{},
		keys:      map[int][]byte{},
		lastTag:   -1,
		lastKey:   -1,
	}
	ts.nextRootKey, ts.sesstagCK = i2pcrypto.HKDF2(rootKey, data, infoKDFDHRatchetStep)
	ts.sesstagCK, ts.symmkeyCK = i2pcrypto.HKDF2(ts.sesstagCK, nil, infoTagAndKeyGenKeys)
	ts.sesstagCK, ts.sesstagConst = i2pcrypto.HKDF2(ts.sesstagCK, nil, infoSTInitialization)
	if isInbound {
		for i := 0; i < minSize; i++ {
			ts.storeNextTag()
		}
	}
	if id > 0 && id <= 65535 {
		ts.acked = true
	}
	return ts
}

// newOutboundNSRTagSet creates the outbound NSR tag set (Bob side: the
// tag set used to send the NSR). Reference: RatchetTagSet ctor "Outbound
// NSR Tagset".
func newOutboundNSRTagSet(state *noise.HandshakeState, rootKey, data []byte) *RatchetTagSet {
	return newRatchetTagSet(rootKey, data, -2, -2, false, state, 0, 0)
}

// newInboundNSRTagSet creates the inbound NSR tag set (Alice side:
// expects the NSR; a tag hit clones the stored state).
func newInboundNSRTagSet(state *noise.HandshakeState, rootKey, data []byte) *RatchetTagSet {
	return newRatchetTagSet(rootKey, data, -2, -2, true, state, minRcvWindowNSR, maxRcvWindowNSR)
}

// newOutboundESTagSet creates an outbound ES tag set.
// Reference: RatchetTagSet ctor "Outbound ES Tagset".
func newOutboundESTagSet(rootKey, data []byte, tagSetID, keyID int) *RatchetTagSet {
	return newRatchetTagSet(rootKey, data, tagSetID, keyID, false, nil, 0, 0)
}

// newInboundESTagSet creates an inbound ES tag set.
func newInboundESTagSet(remoteKey, rootKey, data []byte, tagSetID, keyID int) *RatchetTagSet {
	ts := newRatchetTagSet(rootKey, data, tagSetID, keyID, true, nil, minRcvWindowES, maxRcvWindowES)
	ts.remoteKey = append([]byte(nil), remoteKey...)
	return ts
}

// consumeNext produces the next tag in the chain.
// Reference: RatchetTagSet.consumeNext.
func (ts *RatchetTagSet) consumeNext() []byte {
	if ts.lastTag >= tagSetMax {
		return nil
	}
	var tmp []byte
	ts.sesstagCK, tmp = i2pcrypto.HKDF2(ts.sesstagCK, ts.sesstagConst, infoSessionTagKeyGen)
	ts.lastTag++
	return tmp[:tagLen]
}

// consumeNextKey produces the next symmetric key.
// Reference: RatchetTagSet.consumeNextKey.
func (ts *RatchetTagSet) consumeNextKey() []byte {
	if ts.state != nil {
		// NSR tagset: no symmetric keys; the caller decrypts with the
		// handshake state.
		return nil
	}
	var key []byte
	ts.symmkeyCK, key = i2pcrypto.HKDF2(ts.symmkeyCK, nil, infoSymmetricRatchet)
	ts.lastKey++
	if !ts.isInbound && ts.lastKey == 0 {
		ts.acked = true
	}
	return key
}

// lastKeyOf returns the current key index (used as the ES nonce by the
// sender; the receiver derives it from the tag number).
func (ts *RatchetTagSet) lastKeyOf() int { return ts.lastKey }

// storeNextTag generates and registers a tag with the inbound listener.
// Reference: RatchetTagSet.storeNextTag.
func (ts *RatchetTagSet) storeNextTag() {
	tag := ts.consumeNext()
	if tag == nil {
		return
	}
	ts.tags[ts.lastTag] = tag
	// The listener registration happens in RatchetSKM via the
	// SessionTagListener; here tags stay in the map.
}

// consume looks up an inbound tag. Returns the associated key material
// (or handshake state for NSR tag sets). nil means not found.
// Reference: RatchetTagSet.consume.
func (ts *RatchetTagSet) consume(tag []byte) *TagAndKey {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for tagnum, t := range ts.tags {
		if bytes.Equal(t, tag) {
			delete(ts.tags, tagnum)
			ts.acked = true
			if ts.state != nil {
				// NSR
				ts.addTags(tagnum)
				return &TagAndKey{Tag: tag, State: ts.state}
			}
			if key, ok := ts.keys[tagnum]; ok {
				delete(ts.keys, tagnum)
				ts.addTags(tagnum)
				return &TagAndKey{Tag: tag, Key: key, Nonce: tagnum}
			}
			if tagnum > ts.lastKey {
				for i := ts.lastKey + 1; i < tagnum; i++ {
					ts.keys[i] = ts.consumeNextKey()
				}
				key := ts.consumeNextKey()
				ts.addTags(tagnum)
				return &TagAndKey{Tag: tag, Key: key, Nonce: tagnum}
			}
			return nil // dup or error
		}
	}
	return nil
}

// addTags maintains the inbound lookahead window after a tag is used.
// Reference: RatchetTagSet.addTags.
func (ts *RatchetTagSet) addTags(usedTagNumber int) {
	lookAhead := ts.minSize
	if ts.maxSize > ts.minSize {
		if la := ts.minSize + usedTagNumber/2; la < ts.maxSize {
			lookAhead = la
		} else {
			lookAhead = ts.maxSize
		}
	}
	remaining := ts.lastTag - usedTagNumber
	if toAdd := lookAhead - remaining; toAdd > 0 {
		for i := 0; i < toAdd; i++ {
			ts.storeNextTag()
		}
	}
	trimBehind := ts.minSize
	if tooOld := usedTagNumber - trimBehind; tooOld > 0 {
		for tagnum := range ts.keys {
			if tagnum < tooOld {
				delete(ts.keys, tagnum)
			}
		}
		for tagnum, t := range ts.tags {
			if tagnum < tooOld {
				delete(ts.tags, tagnum)
				_ = t
			}
		}
	}
}

// nextForwardKey returns the NextSessionKey to advertise, generating
// one if the tag set is running low. nil unless outbound ES with
// remaining <= LOW. Reference: RatchetTagSet.getNextKey.
func (ts *RatchetTagSet) nextForwardKey() *NextSessionKey {
	if ts.isInbound || ts.state != nil || ts.remaining() > lowTagRemaining {
		return nil
	}
	if ts.nextKey == nil {
		isFirst := ts.ID == 0
		if isFirst || ts.ID&0x01 != 0 {
			// new keys only needed first time and odd times
			priv, pub, err := GenerateX25519Keypair()
			if err != nil {
				return nil
			}
			ts.nextKeys = &X25519KeyPair{Priv: priv, Pub: pub}
			ts.nextKey = &NextSessionKey{Key: pub, ID: ts.KeyID + 1, IsReverse: false, IsRequest: isFirst}
		} else {
			// even times, just send old ID
			ts.nextKey = &NextSessionKey{ID: ts.KeyID, IsReverse: false, IsRequest: true}
		}
	}
	return ts.nextKey
}

// remaining is the number of unused tags left.
// Reference: RatchetTagSet.remaining.
func (ts *RatchetTagSet) remaining() int {
	nextKey := ts.lastTag + 1
	if ts.isInbound {
		nextKey -= len(ts.tags)
	}
	return tagSetMax + 1 - nextKey
}

// nextRootKeyOf returns the root key for the next DH ratchet.
func (ts *RatchetTagSet) nextRootKeyOf() []byte { return ts.nextRootKey }

// RatchetEntry is what the session hands to the encryptor for an ES
// message. Reference: RatchetEntry.java.
type RatchetEntry struct {
	Tag      []byte
	Key      []byte
	Nonce    int
	TagSetID int
	NextFwd  *NextSessionKey
	NextRev  *NextSessionKey
	Acks     []Ack
}

// Session is one ECIES-Ratchet garlic session with a peer, in either
// role (Alice = NS initiator, Bob = NS responder). It owns the inbound
// tag sets and the current outbound tag set.
// Reference: RatchetSKM.OutboundSession.
type Session struct {
	// Target is the peer's ratchet public key.
	Target []byte
	// DestHash is the peer's destination hash, for inbound routing.
	DestHash []byte

	role noiseRole // alice (NS initiator) or bob

	mu sync.Mutex
	// pending is Alice's stored post-msg1 states awaiting an NSR
	// (cloned per tag hit).
	pending []*noise.HandshakeState
	// nsrTagSets are the tag sets whose tag hit means NSR (Alice
	// inbound NSR; Bob's NSR send tag set is outNSR).
	nsrTagSets []*RatchetTagSet
	// inES / outES are the established ES tag sets.
	inES  *RatchetTagSet
	outES *RatchetTagSet
	// outNSR is Bob's tag set used to send the NSR.
	outNSR *RatchetTagSet
	// hisKey IDs track the DH ratchet state.
	myOBKeyID        int
	myIBKeyID        int
	hisIBKey         *NextSessionKey // his forward key, for our outbound
	hisOBKey         *NextSessionKey // his reverse key, for our inbound
	hisIBKeyWithData *NextSessionKey
	hisOBKeyWithData *NextSessionKey
	myIBKeys         *X25519KeyPair
	myIBKey          *NextSessionKey
	myNextOBKeys     *X25519KeyPair
	myIBKeySendCount int
	nextIBRootKey    []byte
	split            splitKeys
	established      time.Time
	acked            bool
}

type noiseRole int

const (
	roleAlice noiseRole = iota
	roleBob
)

// splitKeys is the Noise split output. Reference: SplitKeys.java.
type splitKeys struct {
	CK  []byte
	Kab []byte
	Kba []byte
}

// noiseSplit computes SplitKeys from a finished HandshakeState.
func noiseSplit(state *noise.HandshakeState) splitKeys {
	ck := state.ChainingKey()
	ab, ba := i2pcrypto.HKDF2(ck, nil, "")
	return splitKeys{CK: ck, Kab: ab, Kba: ba}
}

// newAliceSession creates an Alice-side session: after sending the NS
// (msg1), the state is stored to match the NSR.
// Reference: OutboundSession ctor (initiator branch).
func newAliceSession(target []byte, state *noise.HandshakeState, now time.Time) *Session {
	s := &Session{Target: append([]byte(nil), target...), role: roleAlice, established: now}
	s.addPendingNS(state)
	return s
}

// addPendingNS records a post-msg1 handshake state awaiting the NSR,
// with its reply-tag set. Called for every NS we send while the
// handshake is still open: a retransmitted SYN produces a fresh NS, but
// the NSR for the earlier NS may still be in flight — dropping the
// earlier state here would make that NSR unmatchable and stall the
// connection until it times out. Reference: OutboundSession keeps the
// prior session until the handshake completes.
func (s *Session) addPendingNS(state *noise.HandshakeState) {
	ck := state.ChainingKey()
	tagsetKey := i2pcrypto.HKDF(ck, nil, infoSessionReplyTags)
	s.nsrTagSets = append(s.nsrTagSets, newInboundNSRTagSet(state, ck, tagsetKey))
	s.pending = append(s.pending, state)
}

// newBobSession creates a Bob-side session: after receiving the NS and
// before sending the NSR, the outbound NSR tag set is created from the
// same reply-tagset KDF.
// Reference: OutboundSession ctor (responder branch).
func newBobSession(target []byte, state *noise.HandshakeState, now time.Time) *Session {
	s := &Session{Target: append([]byte(nil), target...), role: roleBob, established: now}
	ck := state.ChainingKey()
	tagsetKey := i2pcrypto.HKDF(ck, nil, infoSessionReplyTags)
	s.outNSR = newOutboundNSRTagSet(state, ck, tagsetKey)
	return s
}

// updateToES moves the session to the established (ES) state after the
// NSR is sent/received. Alice: outES from (rk=split.CK, k_ab), inES
// from (rk, k_ba); Bob mirrored. Reference: OutboundSession.
// updateSession.
func (s *Session) updateToES(state *noise.HandshakeState, now time.Time) {
	sp := noiseSplit(state)
	s.split = sp
	if s.role == roleBob {
		s.inES = newInboundESTagSet(s.Target, sp.CK, sp.Kab, 0, -1)
		s.outES = newOutboundESTagSet(sp.CK, sp.Kba, 0, -1)
		s.outNSR = nil
	} else {
		s.outES = newOutboundESTagSet(sp.CK, sp.Kab, 0, -1)
		s.inES = newInboundESTagSet(s.Target, sp.CK, sp.Kba, 0, -1)
		s.nsrTagSets = nil
		s.pending = nil
	}
	s.acked = true
}

// nextKeyReceived processes a NextKey block from a received payload.
// Reference: OutboundSession.nextKeyReceived.
func (s *Session) nextKeyReceived(key NextSessionKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.IsReverse {
		// Ack of our outbound tag set: advance our outbound DH ratchet
		// to the tag set generated from his new key.
		if key.IsRequest {
			return fmt.Errorf("garlic: invalid req+rev nextkey")
		}
		var hisLastID int = -1
		if s.hisIBKey != nil {
			hisLastID = s.hisIBKey.ID
		}
		if hisLastID != key.ID {
			if hisLastID != key.ID-1 {
				return fmt.Errorf("garlic: nextkey OB: got %d expected %d", key.ID, hisLastID+1)
			}
			if key.Key == nil {
				return fmt.Errorf("garlic: nextkey OB w/o key")
			}
			k := key
			s.hisIBKeyWithData = &k
		} else {
			if key.Key != nil {
				return fmt.Errorf("garlic: nextkey OB with unexpected key data")
			}
			if s.hisIBKeyWithData == nil || s.hisIBKeyWithData.ID != key.ID {
				return fmt.Errorf("garlic: nextkey OB w/o key we don't have")
			}
		}
		var oldtsID int
		if s.myOBKeyID == -1 && hisLastID == -1 {
			oldtsID = 0
		} else {
			oldtsID = 1 + s.myOBKeyID + hisLastID
		}
		oldts := s.outES
		if oldts == nil || oldts.ID != oldtsID {
			return fmt.Errorf("garlic: nextkey OB: no existing OB tagset %d", oldtsID)
		}
		nextKeys := oldts.nextKeys
		if nextKeys == nil {
			if oldtsID == 0 || oldtsID&0x01 != 0 {
				return fmt.Errorf("garlic: nextkey OB: no stored next keys")
			}
			nextKeys = s.myNextOBKeys
		}
		shared, err := x25519DH(nextKeys.Priv, s.hisIBKeyWithData.Key)
		if err != nil {
			return err
		}
		ssk := i2pcrypto.HKDF(shared, nil, infoXDHRatchetTagSet)
		newtsID := oldtsID + 1
		s.outES = newOutboundESTagSet(oldts.nextRootKeyOf(), ssk, newtsID, s.myOBKeyID)
		s.myNextOBKeys = nil
	} else {
		// About our inbound tag set: generate our reverse key, advance
		// the inbound DH ratchet.
		var hisLastID int = -1
		if s.hisOBKey != nil {
			hisLastID = s.hisOBKey.ID
		}
		if hisLastID != key.ID {
			if hisLastID != key.ID-1 {
				return fmt.Errorf("garlic: nextkey IB: got %d expected %d", key.ID, hisLastID+1)
			}
			if key.Key == nil {
				return fmt.Errorf("garlic: nextkey IB w/o key")
			}
			k := key
			s.hisOBKeyWithData = &k
		} else {
			if key.Key != nil {
				return fmt.Errorf("garlic: nextkey IB with unexpected key data")
			}
			if s.hisOBKeyWithData == nil || s.hisOBKeyWithData.ID != key.ID {
				return fmt.Errorf("garlic: nextkey IB w/o key we don't have")
			}
		}
		if s.nextIBRootKey == nil {
			return fmt.Errorf("garlic: nextkey IB: no next root key")
		}
		var oldtsID int
		if s.myIBKeyID == -1 && hisLastID == -1 {
			oldtsID = 0
		} else {
			oldtsID = 1 + s.myIBKeyID + hisLastID
		}
		if oldtsID&0x01 == 0 {
			// new keys for 0, 2, 4, ...
			priv, pub, err := GenerateX25519Keypair()
			if err != nil {
				return err
			}
			s.myIBKeys = &X25519KeyPair{Priv: priv, Pub: pub}
			s.myIBKeyID++
			s.myIBKey = &NextSessionKey{Key: pub, ID: s.myIBKeyID, IsReverse: true}
		} else {
			// reuse keys for 1, 3, 5, ...
			if s.myIBKeys == nil {
				return fmt.Errorf("garlic: nextkey IB: no old keys")
			}
			s.myIBKey = &NextSessionKey{ID: s.myIBKeyID, IsReverse: true}
		}
		s.hisOBKey = &key
		shared, err := x25519DH(s.myIBKeys.Priv, s.hisOBKeyWithData.Key)
		if err != nil {
			return err
		}
		ssk := i2pcrypto.HKDF(shared, nil, infoXDHRatchetTagSet)
		newtsID := oldtsID + 1
		s.inES = newInboundESTagSet(s.Target, s.nextIBRootKey, ssk, newtsID, s.myIBKeyID)
		s.nextIBRootKey = s.inES.nextRootKeyOf()
	}
	return nil
}

// myNextOBKeys holds our generated outbound keys between the
// nextForwardKey advertisement and the ack.
var _ = rand.Reader

// consumeNext returns the outbound ES entry (tag+key+nonce plus any
// next-key announcements and acks to piggyback). nil if no established
// outbound tag set remains.
// Reference: OutboundSession.consumeNext.
func (s *Session) consumeNext() *RatchetEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.outES
	if ts == nil {
		return nil
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tag := ts.consumeNext()
	if tag == nil {
		s.outES = nil
		return nil
	}
	key := ts.consumeNextKey()
	// The ES nonce is the key index in the symmkey chain (the receiver
	// uses the tag number, which advances in lockstep).
	// Reference: RatchetTagSet.consumeNextKey.
	entry := &RatchetEntry{
		Tag:      tag[:tagLen],
		Key:      key,
		Nonce:    ts.lastKeyOf(),
		TagSetID: ts.ID,
		NextFwd:  ts.nextForwardKey(),
		NextRev:  s.reverseSendKey(),
	}
	if entry.NextFwd != nil && s.myNextOBKeys == nil && ts.nextKeys != nil {
		s.myNextOBKeys = ts.nextKeys
	}
	return entry
}

// reverseSendKey returns our inbound key announcement to send, if any.
// Reference: OutboundSession.getReverseSendKey.
func (s *Session) reverseSendKey() *NextSessionKey {
	if s.myIBKey == nil {
		return nil
	}
	s.myIBKeySendCount++
	if s.myIBKeySendCount > 128 {
		return nil
	}
	return s.myIBKey
}

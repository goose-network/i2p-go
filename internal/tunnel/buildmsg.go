// Short Tunnel Build Message (STBM) assembly and reply handling for our
// 1-hop inbound tunnels [R = IBGW, we = IBEP].
//
// STBM (I2NP type 25): [1-byte record count][records (218 bytes each)].
// We use a 4-slot STBM (BuildRequestor.SHORT_RECORDS): one slot holds R's
// encrypted request record, one holds our blank IBEP record, and two hold
// pure random blanks.
//
// IBEP blank record (BuildMessageGenerator.createRecord): [16B truncated
// our-hash][32B ephemeral X25519 pub][random]. We keep SHA-256 of the
// whole record so we can verify it in the reply. The ephemeral key is
// throwaway — nobody can decrypt the record.
//
// Record layering (BuildMessageGenerator.layeredEncrypt): R will
// ChaCha20-encrypt every record except its own with its reply key when it
// processes the STBM (BuildMessageProcessor.decrypt). ChaCha20 is XOR-
// symmetric, so we pre-apply one layer with R's reply key to the IBEP
// blank; R's re-application cancels it and the blank returns in its
// original form. Pure blanks are skipped (isBlank && hop+1 != length).
//
// Reply path (1-hop inbound, BuildHandler.handleReq): R is an IBGW, not
// an OBEP, so it fills the first null slot — its own, which it nulled
// during decrypt — with a BuildResponseRecord, sets the STBM message ID to
// our replyMessageId, and sends the whole mutated STBM directly to us
// over NTCP2 (nextPeer = us). We verify the blank hash and decrypt R's
// response with its reply key (AD = handshake hash, nonce = slot).
//
// Reference: ShortTunnelBuildMessage.java, BuildRequestor.java,
// BuildMessageGenerator.java, BuildMessageProcessor.java,
// BuildHandler.java, BuildResponseRecord.java.
package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
	"github.com/goose-network/i2p-go/internal/i2pcrypto"
)

// shortRecords is the STBM slot count for tunnels of our length.
// Reference: BuildRequestor.SHORT_RECORDS (4, used when the tunnel
// length is <= 4).
const shortRecords = 4

// BuildResult is the outcome of parsing a tunnel-build reply.
type BuildResult struct {
	// Accepted is true when the participating hop replied 0.
	Accepted bool
	// Status is the hop's response code (for diagnostics).
	Status int
}

// inboundBuildState carries the ephemeral state of one 1-hop inbound
// tunnel build [R = IBGW, we = IBEP]. Created by newInboundBuild,
// completed by encodeSTBM, resolved by ParseBuildReply.
type inboundBuildState struct {
	// RHash is R's router hash.
	RHash data.Hash
	// RTunnelID is the tunnel ID R receives on (the one we put in its
	// record and the one we use when sending TunnelGateway data to R).
	RTunnelID uint32
	// IBEPTunnelID is the tunnel ID WE receive on (R's sendTunnelId; the
	// "nextTunnel" in R's record).
	IBEPTunnelID uint32
	// ReplyMessageID correlates the build reply.
	ReplyMessageID uint32

	rec *shortRecord
	ri  *data.RouterInfo
	now time.Time

	// Filled by encodeSTBM:
	// RKeys are the keys derived for R's hop (kept for the reply).
	RKeys *HopKeys
	// BlankHash is SHA-256 of the IBEP blank record.
	BlankHash []byte
	// Order maps record slot -> hop number (0 = R, 1 = IBEP blank,
	// 2/3 = pure blanks).
	Order []int
	// IBEPSlot is the slot of our blank IBEP record.
	IBEPSlot int
	// RSlot is the slot of R's request record.
	RSlot int
}

// newInboundBuild starts a 1-hop inbound tunnel build through R.
// replyMessageID correlates the reply. The caller completes it with
// encodeSTBM.
func newInboundBuild(ri *data.RouterInfo, replyMessageID uint32, now time.Time) (*inboundBuildState, error) {
	if ri.Identity.EncType != data.EncECIES_X25519 {
		return nil, fmt.Errorf("tunnel: R enc type %d", ri.Identity.EncType)
	}
	recvTunnel := randomTunnelID() // R's receive ID
	ibepTunnel := randomTunnelID() // our receive ID
	rec := &shortRecord{
		recvTunnel: recvTunnel,
		nextTunnel: ibepTunnel, // R's sendTunnelId = our IBEP receive ID
		isInGW:     true,
		nextMsgID:  replyMessageID,
	}
	return &inboundBuildState{
		RHash:          ri.RouterHash(),
		RTunnelID:      recvTunnel,
		IBEPTunnelID:   ibepTunnel,
		ReplyMessageID: replyMessageID,
		rec:            rec,
		ri:             ri,
		now:            now,
	}, nil
}

// randomTunnelID picks a nonzero 4-byte tunnel ID.
func randomTunnelID() uint32 {
	for {
		id := binary.BigEndian.Uint32(randomBytes(4))
		if id != 0 && id <= 0xFFFFFF00 {
			return id
		}
	}
}

// encodeSTBM produces the STBM with our records placed and layered.
// ourHash is our router hash (the IBEP / reply target).
func (s *inboundBuildState) encodeSTBM(ourHash data.Hash) (*i2np.Message, error) {
	// Slot assignment: hop 0 = R (IBGW), hop 1 = IBEP blank, hops 2-3 =
	// pure blanks, shuffled among the 4 slots.
	order := []int{0, 1, 2, 3}
	shuffle(order)
	s.Order = order

	s.rec.nextIdent = ourHash // R's next hop: us, the IBEP

	records := make([][]byte, shortRecords)
	var rKeys *HopKeys
	ibepSlot, rSlot := -1, -1
	for slot, hop := range order {
		switch hop {
		case 0:
			// R's record: Noise-encrypted to R's X25519 key.
			enc, keys, err := encryptShortRecord(s.rec, s.ri.Identity.EncKey, s.RHash, func() time.Time { return s.now })
			if err != nil {
				return nil, err
			}
			records[slot] = enc
			rKeys = keys
			rSlot = slot
		case 1:
			// IBEP blank: [16B truncated our-hash][32B ephemeral pub]
			// + random; we remember SHA-256 of the whole record.
			blank := make([]byte, ShortRecordSize)
			copy(blank[:BuildPeerSize], ourHash[:BuildPeerSize])
			priv := randomBytes(32)
			pub := x25519Pub(priv)
			copy(blank[BuildPeerSize:BuildPeerSize+32], pub)
			rand.Read(blank[BuildPeerSize+32:])
			h := sha256.Sum256(blank)
			s.BlankHash = h[:]
			records[slot] = blank
			ibepSlot = slot
		default:
			// Pure random blank.
			records[slot] = randomBytes(ShortRecordSize)
		}
	}
	if rKeys == nil || ibepSlot < 0 {
		return nil, fmt.Errorf("tunnel: slot assignment bug")
	}
	s.RKeys = rKeys
	s.IBEPSlot = ibepSlot
	s.RSlot = rSlot

	// Pre-cancel R's re-layering of the IBEP blank: R ChaCha20-encrypts
	// every non-own record with its reply key, so we apply the same
	// transform now; the two cancel. Pure blanks (hops 2-3) are skipped
	// by layeredEncrypt's isBlank check, so they stay unlayered.
	// Reference: BuildMessageGenerator.layeredEncrypt.
	chacha20Block(rKeys.ReplyKey, uint32(ibepSlot), records[ibepSlot])

	// Serialize the STBM body: 1-byte count + records.
	body := make([]byte, 0, 1+shortRecords*ShortRecordSize)
	body = append(body, byte(shortRecords))
	for _, r := range records {
		body = append(body, r...)
	}
	msg := i2np.New(i2np.TypeShortTunnelBuild, body)
	msg.ID = s.ReplyMessageID
	return msg, nil
}

// ParseBuildReply handles the mutated STBM that R sends back to us
// directly (the 1-hop inbound reply path). It verifies our blank IBEP
// record by SHA-256 and decrypts R's response record.
// Reference: BuildReplyHandler.decrypt (short branch) + handleReply.
func (s *inboundBuildState) ParseBuildReply(msg *i2np.Message) (*BuildResult, error) {
	if msg.Type != i2np.TypeShortTunnelBuild {
		return nil, fmt.Errorf("tunnel: reply type %d", msg.Type)
	}
	b := msg.Payload
	if len(b) != 1+shortRecords*ShortRecordSize || int(b[0]) != shortRecords {
		return nil, fmt.Errorf("tunnel: reply size %d", len(b))
	}
	records := make([][]byte, shortRecords)
	for i := range records {
		records[i] = b[1+i*ShortRecordSize : 1+(i+1)*ShortRecordSize]
	}
	// The blank comes back in its original form: our pre-layer cancels
	// R's re-layer. Verify by SHA-256.
	h := sha256.Sum256(records[s.IBEPSlot])
	if !bytesEqual(h[:], s.BlankHash) {
		return nil, fmt.Errorf("tunnel: IBEP blank hash mismatch")
	}
	// R's response record: ChaChaPoly with R's reply key, AD = R's
	// handshake hash, nonce = R's slot.
	status, err := decryptResponseRecord(records[s.RSlot], s.RKeys.ReplyKey, s.RKeys.ReplyAD, s.RSlot)
	if err != nil {
		return nil, fmt.Errorf("tunnel: R response decrypt: %w", err)
	}
	return &BuildResult{Accepted: status == 0, Status: status}, nil
}

// decryptResponseRecord opens a 218-byte short build response record:
// the entire record is the AEAD ciphertext+MAC.
// Reference: BuildResponseRecord.decrypt (short) — ChaChaPoly with the
// 8-byte-nonce layout, nonce = slot number; status at pt[201].
func decryptResponseRecord(rec []byte, key, ad []byte, slot int) (int, error) {
	if len(rec) != ShortRecordSize {
		return -1, fmt.Errorf("tunnel: response record size %d", len(rec))
	}
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(uint64(slot))
	pt, err := a.Open(ad, rec)
	if err != nil {
		return -1, err
	}
	if len(pt) != ShortRecordSize-16 {
		return -1, fmt.Errorf("tunnel: response pt size %d", len(pt))
	}
	return int(pt[ShortRecordSize-17]), nil
}

// buildResponseRecord creates R's side: a short response record (for
// tests and for when we act as a hop). The whole 218-byte record is
// AEAD output: [202-byte plaintext][16-byte MAC].
// Reference: BuildResponseRecord.createShort.
func buildResponseRecord(status int, key, ad []byte, slot int, props map[string]string) []byte {
	rv := make([]byte, ShortRecordSize)
	off := copy(rv, encodeProperties(props))
	rand.Read(rv[off : ShortRecordSize-17])
	rv[ShortRecordSize-17] = byte(status)
	a := i2pcrypto.NewAEAD(key)
	a.SetNonce(uint64(slot))
	ct := a.Seal(ad, rv[:ShortRecordSize-16])
	copy(rv, ct)
	return rv
}

// shuffle randomizes the order (Fisher-Yates).
func shuffle(p []int) {
	for i := len(p) - 1; i > 0; i-- {
		j := int(binary.BigEndian.Uint32(randomBytes(4))) % (i + 1)
		p[i], p[j] = p[j], p[i]
	}
}

// x25519Pub derives the public key for a 32-byte private scalar.
func x25519Pub(priv []byte) []byte {
	pub, err := curve25519X25519(priv, curveBase)
	if err != nil {
		panic(err) // only for malformed scalars, which we never pass
	}
	return pub
}

var curveBase = basePoint()

func basePoint() []byte {
	b := make([]byte, 32)
	b[0] = 9
	return b
}

func curve25519X25519(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}

// bytesEqual is a tiny helper to avoid importing bytes for one call.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

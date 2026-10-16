// HandleRequest: when a peer's STBM arrives addressed to us as a hop
// (R=IBGW for their inbound tunnel), decrypt our record, join the
// tunnel, fill our response slot, and send the mutated STBM on.
//
// Our architecture only ever joins as IBGW (1-hop inbound tunnels for
// others) — we never act as OBEP or mid-hop, since our own outbound
// tunnels are 0-hop.
//
// Reference: BuildMessageProcessor.decrypt, BuildHandler.handleReq
// (isInGW branch).
package tunnel

import (
	"fmt"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// IncomingBuild is one decrypted build request while we act as a hop.
type IncomingBuild struct {
	// Record is our decrypted short record.
	Record *shortRecord
	// Keys are the keys we derived for our hop.
	Keys *HopKeys
	// ResponseSlot is the record slot that held our request (and will
	// hold our response).
	ResponseSlot int
	// Records are all slots after our decrypt-layering pass.
	Records [][]byte
	// MsgID is the STBM's I2NP message ID.
	MsgID uint32
	// From is the sending router's hash (transport-level).
	From data.Hash
}

// ParseIncomingSTBM matches and decrypts our record in an incoming
// STBM. ourHash is our router hash, ourPriv our ECIES private key.
// Returns nil if no record targets us (normal for transit noise).
// Reference: BuildMessageProcessor.decrypt.
func ParseIncomingSTBM(msg *i2np.Message, ourHash data.Hash, ourPriv []byte, from data.Hash) (*IncomingBuild, error) {
	if msg.Type != i2np.TypeShortTunnelBuild {
		return nil, fmt.Errorf("tunnel: not an STBM: type %d", msg.Type)
	}
	b := msg.Payload
	if len(b) < 1 {
		return nil, fmt.Errorf("tunnel: empty STBM")
	}
	count := int(b[0])
	if count <= 0 || count > buildMaxRecords {
		return nil, fmt.Errorf("tunnel: STBM record count %d", count)
	}
	if len(b) != 1+count*ShortRecordSize {
		return nil, fmt.Errorf("tunnel: STBM size %d for %d records", len(b), count)
	}
	records := make([][]byte, count)
	for i := 0; i < count; i++ {
		records[i] = b[1+i*ShortRecordSize : 1+(i+1)*ShortRecordSize]
	}
	ourHop := -1
	var rec *shortRecord
	var keys *HopKeys
	for i, r := range records {
		if bytesEqual(r[:BuildPeerSize], ourHash[:BuildPeerSize]) {
			r2, k2, err := decryptShortRecord(r, ourPriv)
			if err != nil {
				continue
			}
			rec, keys, ourHop = r2, k2, i
			break
		}
	}
	if rec == nil {
		return nil, nil
	}
	// Layer-encrypt the other records with our reply key (the mirror
	// of the creator's pre-decrypt). Reference: BuildMessageProcessor
	// .decrypt (isShort branch).
	for i := 0; i < count; i++ {
		if i != ourHop {
			chacha20Block(keys.ReplyKey, uint32(i), records[i])
		}
	}
	return &IncomingBuild{
		Record:       rec,
		Keys:         keys,
		ResponseSlot: ourHop,
		Records:      records,
		MsgID:        msg.ID,
		From:         from,
	}, nil
}

// BuildReplySTBM fills our response slot in the mutated STBM and
// returns the message to send to the next hop (or, for an IBGW with
// replyRouter = the creator, directly back to the creator).
// ib (the IncomingBuild) records are mutated in place.
// Reference: BuildHandler.handleReq reply-send tail.
func (ib *IncomingBuild) BuildReplySTBM(status int) *i2np.Message {
	// Our response record: ChaChaPoly with our reply key, AD = our
	// handshake hash, nonce = our slot.
	ib.Records[ib.ResponseSlot] = buildResponseRecord(status, ib.Keys.ReplyKey, ib.Keys.ReplyAD, ib.ResponseSlot, nil)

	body := make([]byte, 0, 1+len(ib.Records)*ShortRecordSize)
	body = append(body, byte(len(ib.Records)))
	for _, r := range ib.Records {
		body = append(body, r...)
	}
	out := i2np.New(i2np.TypeShortTunnelBuild, body)
	// The mutated STBM's message ID becomes the reply message ID from
	// our decrypted record (R sends it back with that ID so the
	// creator can correlate).
	out.ID = ib.Record.nextMsgID
	return out
}

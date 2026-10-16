// NetDB store client: publishing our LeaseSet2 to a floodfill.
//
// The store is a DatabaseStore message sent directly to the floodfill
// (Java sends stores through an exploratory tunnel when it has one; a
// direct send is equivalent for the floodfill, which processes the
// message wherever it arrives). The ReplyToken carries a nonce; the
// floodfill answers with a DeliveryStatusMessage when the store is
// complete (FloodfillDatabaseStoreMessageHandler replies with the
// token's nonce through the reply path — direct, since our lookup
// arrived direct).
//
// Reference: FloodfillStoreJob.java,
// FloodfillDatabaseStoreMessageHandler.java.
package netdb

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// StoreClient publishes LeaseSet2s to floodfills.
type StoreClient struct {
	db     *NetDB
	sender Sender

	// Log, when non-nil, receives one line per failed store attempt
	// (each failure falls through to the next floodfill).
	Log *log.Logger

	mu      sync.Mutex
	pending map[uint32]chan uint32
	next    uint32
	now     func() time.Time
}

// NewStoreClient creates a store client.
func NewStoreClient(db *NetDB, sender Sender) *StoreClient {
	return &StoreClient{
		db:      db,
		sender:  sender,
		pending: make(map[uint32]chan uint32),
		now:     time.Now,
	}
}

// StoreLS2 publishes a LeaseSet2 to a floodfill and waits for the
// delivery-status confirmation. Kademlia store placement: the closest
// floodfills to the key hold the entry, so we try them in order (a
// store anywhere is flooded onward, but a close store is the one
// lookups find). On a send failure or confirmation timeout the next
// floodfill is tried.
func (c *StoreClient) StoreLS2(ctx context.Context, ls *data.LeaseSet2) error {
	key := data.DestinationHash(ls.Destination)
	peers := c.db.ClosestFloodfills(key, maxStorePeers, nil)
	if len(peers) == 0 {
		return fmt.Errorf("netdb: no floodfills known")
	}

	var lastErr error
	for _, ri := range peers {
		if err := c.storeOne(ctx, key, ls, ri.RouterHash()); err != nil {
			lastErr = err
			if c.Log != nil {
				c.Log.Printf("netdb store to %s failed: %v", ri.RouterHash().ToI2PBase64()[:8], err)
			}
			continue // try the next floodfill
		}
		return nil
	}
	return lastErr
}

// maxStorePeers bounds the store fan-out. Most close floodfills are
// unreachable from a NAT'd network (the dial fails or the handshake
// times out), so try generously — one confirmed store is a success.
// Reference: FloodfillStoreJob (store to the K closest floodfills).
const maxStorePeers = 6

// storeOne sends one store message to a floodfill and waits for its
// DeliveryStatus.
func (c *StoreClient) storeOne(ctx context.Context, key data.Hash, ls *data.LeaseSet2, target data.Hash) error {
	// Nonce for the reply correlation.
	c.mu.Lock()
	c.next++
	nonce := c.next
	ch := make(chan uint32, 1)
	c.pending[nonce] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, nonce)
		c.mu.Unlock()
	}()

	ls2Bytes := ls.Bytes()
	store := &i2np.DatabaseStore{
		Key:        key,
		Kind:       i2np.DbLeaseSet2,
		ReplyToken: nonce,
		// With a non-zero token the reply path follows: 4-byte reply
		// tunnel ID (0 = reply directly to the reply gateway's router
		// hash, not through a tunnel) + 32-byte gateway hash. We are
		// unreachable, so we ask the floodfill to send the
		// DeliveryStatus straight back over this NTCP2 connection.
		// Reference: FloodfillDatabaseStoreMessageHandler.java;
		// i2pd NetDb.cpp (replyToken) → SendMessage(replyIdent, ...).
		ReplyTunnel:  0,
		ReplyGateway: c.db.OurHash,
		Entry:        ls2Bytes,
	}
	msg := i2np.New(i2np.TypeDatabaseStore, store.Payload())
	msg.Expiration = time.Now().Add(2 * time.Minute)
	if err := c.sender.SendI2NP(target, msg.Encode9()); err != nil {
		return fmt.Errorf("netdb: store send: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()
	select {
	case n := <-ch:
		if n != nonce {
			return fmt.Errorf("netdb: store reply nonce mismatch %d", n)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("netdb: store confirmation timed out")
	}
}

// HandleDeliveryStatus feeds one DeliveryStatus message into pending
// stores. Returns true when matched.
// Reference: FloodfillDatabaseStoreMessageHandler reply +
// DeliveryStatusMessage.
func (c *StoreClient) HandleDeliveryStatus(raw []byte) bool {
	msg, err := i2np.Decode9(raw)
	if err != nil || msg.Type != i2np.TypeDeliveryStatus {
		return false
	}
	ds, err := i2np.ParseDeliveryStatus(msg.Payload)
	if err != nil {
		return false
	}
	c.mu.Lock()
	ch := c.pending[ds.ID]
	c.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- ds.ID:
	default:
	}
	return true
}

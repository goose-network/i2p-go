// NetDB lookup and store clients. Lookups are sent directly to
// floodfill routers over NTCP2 (no reply tunnel: the floodfill replies
// directly to the sender — HandleDatabaseLookupMessageJob.sendMessage
// with replyTunnel == null). Replies are matched by key, like Java's
// FloodOnlyLookupSelector.
//
// Reference: IterativeSearchJob.java, FloodOnlyLookupSelector.java,
// HandleDatabaseLookupMessageJob.java, FloodfillDatabaseStoreMessageHandler.
package netdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// Sender sends a raw (NTCP2-format) I2NP message to a router hash.
// The router layer supplies this (NTCP2 connection manager).
type Sender interface {
	SendI2NP(to data.Hash, raw []byte) error
}

// LookupClient runs iterative lookups over direct NTCP2 sends.
type LookupClient struct {
	db     *NetDB
	sender Sender
	now    func() time.Time

	mu      sync.Mutex
	pending map[data.Hash]*pendingLookup
}

// pendingLookup fans replies out to waiting lookups for one key.
type pendingLookup struct {
	key     data.Hash
	isLS2   bool
	waiters []chan *i2np.Message
	created time.Time
}

// NewLookupClient creates a client over a sender.
func NewLookupClient(db *NetDB, sender Sender) *LookupClient {
	return &LookupClient{
		db:      db,
		sender:  sender,
		now:     time.Now,
		pending: make(map[data.Hash]*pendingLookup),
	}
}

// LookupTimeout bounds one lookup round.
const LookupTimeout = 15 * time.Second

// LookupRI fetches a RouterInfo by hash from the floodfills.
// Reference: IterativeSearchJob (single-key variant).
func (c *LookupClient) LookupRI(ctx context.Context, key data.Hash) (*data.RouterInfo, error) {
	if ri := c.db.GetRI(key); ri != nil {
		return ri, nil
	}
	raw, err := c.lookup(ctx, key, false)
	if err != nil {
		return nil, err
	}
	ds, err := i2np.ParseDatabaseStore(raw.Payload)
	if err != nil {
		return nil, fmt.Errorf("netdb: bad store reply: %w", err)
	}
	if ds.Kind != i2np.DbRouterInfo {
		return nil, fmt.Errorf("netdb: reply kind %d for RI lookup", ds.Kind)
	}
	ri, err := data.ReadRouterInfo(ds.RouterInfo, true)
	if err != nil {
		return nil, fmt.Errorf("netdb: bad RI in reply: %w", err)
	}
	if ri.RouterHash() != key {
		return nil, fmt.Errorf("netdb: RI hash mismatch")
	}
	c.db.StoreRI(&ri)
	return &ri, nil
}

// LookupLS2 fetches a LeaseSet2 by destination hash.
func (c *LookupClient) LookupLS2(ctx context.Context, key data.Hash) (*data.LeaseSet2, error) {
	if ls := c.db.GetLS2(key); ls != nil {
		return ls, nil
	}
	raw, err := c.lookup(ctx, key, true)
	if err != nil {
		return nil, err
	}
	ds, err := i2np.ParseDatabaseStore(raw.Payload)
	if err != nil {
		return nil, fmt.Errorf("netdb: bad store reply: %w", err)
	}
	if ds.Kind == i2np.DbRouterInfo {
		return nil, fmt.Errorf("netdb: RI reply for LS2 lookup")
	}
	ls, err := data.ReadLeaseSet2(ds.Entry, true)
	if err != nil {
		return nil, fmt.Errorf("netdb: bad LS2 in reply: %w", err)
	}
	if data.DestinationHash(ls.Destination) != key {
		return nil, fmt.Errorf("netdb: LS2 hash mismatch")
	}
	c.db.StoreLS2(ls)
	return ls, nil
}

// lookup sends the DatabaseLookup to the floodfills (up to
// maxLookupPeers, in parallel) and waits for the first matching reply.
func (c *LookupClient) lookup(ctx context.Context, key data.Hash, isLS2 bool) (*i2np.Message, error) {
	peers := c.db.Floodfills()
	if len(peers) == 0 {
		return nil, fmt.Errorf("netdb: no floodfills known")
	}
	if len(peers) > maxLookupPeers {
		peers = peers[:maxLookupPeers]
	}

	// Register the waiter before sending (replies may race the send).
	ch := c.addWaiter(key, isLS2)
	defer c.removeWaiter(key, ch)

	var flags byte = i2np.FlagRI
	if isLS2 {
		flags = i2np.FlagLS
	}
	for _, ri := range peers {
		lk := &i2np.DatabaseLookup{
			Key:   key,
			From:  c.db.OurHash,
			Flags: flags,
		}
		msg := i2np.New(i2np.TypeDatabaseLookup, lk.Payload())
		if err := c.sender.SendI2NP(ri.RouterHash(), msg.Encode9()); err != nil {
			continue // try the next floodfill
		}
	}

	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()
	select {
	case m := <-ch:
		return m, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("netdb: lookup for %s timed out", key.ToI2PBase64()[:8])
	}
}

// maxLookupPeers bounds the fan-out. Reference: SEARCH_BREDTH.
const maxLookupPeers = 3

// addWaiter registers interest in replies for a key.
func (c *LookupClient) addWaiter(key data.Hash, isLS2 bool) chan *i2np.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[key]
	if p == nil {
		p = &pendingLookup{key: key, isLS2: isLS2, created: c.now()}
		c.pending[key] = p
	}
	ch := make(chan *i2np.Message, 1)
	p.waiters = append(p.waiters, ch)
	return ch
}

// removeWaiter unregisters a waiter.
func (c *LookupClient) removeWaiter(key data.Hash, ch chan *i2np.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[key]
	if p == nil {
		return
	}
	for i, w := range p.waiters {
		if w == ch {
			p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
			break
		}
	}
	if len(p.waiters) == 0 {
		delete(c.pending, key)
	}
}

// HandleReply feeds one inbound raw (NTCP2-format) I2NP message from a
// floodfill into any pending lookup. It returns true when the message
// matched a pending lookup. The router calls this for every directly
// received DatabaseStore / DatabaseSearchReply.
// Reference: FloodOnlyLookupSelector.isMatch.
func (c *LookupClient) HandleReply(raw []byte) bool {
	msg, err := i2np.Decode9(raw)
	if err != nil {
		return false
	}
	switch msg.Type {
	case i2np.TypeDatabaseStore:
		ds, err := i2np.ParseDatabaseStore(msg.Payload)
		if err != nil {
			return false
		}
		return c.dispatchReply(ds.Key, msg)
	case i2np.TypeDatabaseSearchReply:
		dsr, err := i2np.ParseDatabaseSearchReply(msg.Payload)
		if err != nil {
			return false
		}
		// Chase the hashes: store any RIs the floodfill sent back, then
		// keep waiting for the real answer (a DSR is a miss).
		for _, h := range dsr.Peers {
			go func(h data.Hash) {
				ctx, cancel := context.WithTimeout(context.Background(), LookupTimeout)
				defer cancel()
				c.LookupRI(ctx, h) // best effort
			}(h)
		}
		return false
	}
	return false
}

// dispatchReply wakes the waiters for a key.
func (c *LookupClient) dispatchReply(key data.Hash, msg *i2np.Message) bool {
	c.mu.Lock()
	p := c.pending[key]
	c.mu.Unlock()
	if p == nil {
		return false
	}
	for _, w := range p.waiters {
		select {
		case w <- msg:
		default:
		}
	}
	return true
}

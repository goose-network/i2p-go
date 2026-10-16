// NetDB lookup and store clients. Lookups are iterative searches sent
// directly to floodfill routers over NTCP2 (no reply tunnel: the
// floodfill replies directly to the sender —
// HandleDatabaseLookupMessageJob.sendMessage with replyTunnel == null).
//
// Each round queries the floodfills whose hashes are XOR-closest to
// the key's routing key; a DatabaseSearchReply miss points at closer
// floodfills, whose RIs we fetch and query next, until one returns a
// DatabaseStore carrying the answer.
//
// Reference: IterativeSearchJob.java, FloodOnlyLookupSelector.java,
// HandleDatabaseLookupMessageJob.java.
package netdb

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	// Log, when non-nil, receives one line per lookup round for
	// debugging against the live network.
	Log *log.Logger

	chaseMu sync.Mutex
	chases  int // RI fetches in flight

	mu      sync.Mutex
	pending map[data.Hash]*pendingLookup
}

// pendingLookup fans replies out to waiting lookups for one key. At
// most one waiter runs the iterative search at a time (searching);
// the others join it and receive the same dispatched replies. done is
// closed when the active search exits, waking joiners to take over.
type pendingLookup struct {
	key       data.Hash
	isLS2     bool
	waiters   []*lookupWaiter
	created   time.Time
	searching bool
	done      chan struct{}
}

// lookupWaiter is one caller's view of a pending lookup: the answer
// (a DatabaseStore reply) or a miss (a DatabaseSearchReply's closer
// floodfills).
type lookupWaiter struct {
	reply chan *i2np.Message
	miss  chan []data.Hash
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

// LookupTimeout bounds one lookup (all rounds). Iterative searches
// chase DatabaseSearchReply pointers through the floodfill overlay,
// so several round-trips plus RI fetches must fit; the SOCKS layer
// allows 75s.
const LookupTimeout = 45 * time.Second

// maxLookupPeers bounds the fan-out per round. Reference:
// SEARCH_BREDTH (2-3 parallel peers per iterative search round).
const maxLookupPeers = 3

// reselectDelay is how long a round waits before re-selecting
// candidates: background RI fetches keep storing new floodfills, and
// the next wave should pick them up.
const reselectDelay = 2 * time.Second

// chaseTimeout bounds each background RI fetch for floodfills
// suggested by a DatabaseSearchReply.
const chaseTimeout = 10 * time.Second

// stragglerGrace is how long a fully-exhausted search keeps waiting
// for a reply already in flight.
const stragglerGrace = 5 * time.Second

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
	if dir := os.Getenv("I2PGO_DUMP_LS2"); dir != "" {
		// Diagnostic: keep the exact bytes the network served, for
		// offline analysis of interop problems.
		_ = os.WriteFile(filepath.Join(dir, key.ToI2PBase64()+".ls2"), ds.Entry, 0o644)
	}
	c.db.StoreLS2(ls)
	return ls, nil
}

// lookup runs the iterative search: query the closest known
// floodfills, follow DatabaseSearchReply pointers to closer ones, and
// return the first DatabaseStore answer.
// Reference: IterativeSearchJob (search key → peers → replies).
//
// Concurrent lookups for one key share a single search: the first
// caller runs the rounds; later callers join its dispatched replies
// (and take the search over if it ends unanswered while they still
// have time — reference: SearchState joining).
func (c *LookupClient) lookup(ctx context.Context, key data.Hash, isLS2 bool) (*i2np.Message, error) {
	if len(c.db.Floodfills()) == 0 {
		return nil, fmt.Errorf("netdb: no floodfills known")
	}
	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()

	for {
		// Register the waiter before sending (replies may race the send).
		w, p, searcher := c.addWaiter(key, isLS2)
		if searcher {
			m, err := c.runSearch(ctx, key, isLS2, w)
			// Order matters: leaving the waiter list first keeps joiners
			// woken by endSearch from racing a re-registration against
			// removeWaiter (which could otherwise delete the pending
			// entry out from under them).
			c.removeWaiter(key, w)
			c.endSearch(key)
			return m, err
		}

		// Join the active search: answers arrive via dispatchReply;
		// misses are followed by the searcher, not by us.
		select {
		case m := <-w.reply:
			c.removeWaiter(key, w)
			return m, nil
		case <-p.done:
			c.removeWaiter(key, w)
			// The answer may have been dispatched to us just before the
			// search exited; delivering it beats restarting the search.
			select {
			case m := <-w.reply:
				return m, nil
			default:
			}
			// The search ended without an answer; a fresh search with
			// our remaining budget may still reach closer floodfills.
			continue
		case <-ctx.Done():
			c.removeWaiter(key, w)
			// A reply may already be queued (it can land while this
			// loop is between rounds). Delivering it beats failing.
			select {
			case m := <-w.reply:
				return m, nil
			default:
			}
			return nil, fmt.Errorf("netdb: lookup for %s timed out", key.ToI2PBase64()[:8])
		}
	}
}

// runSearch is the round loop for one key, owned by one waiter. The
// reply and miss channels are that waiter's (dispatch fills them).
func (c *LookupClient) runSearch(ctx context.Context, key data.Hash, isLS2 bool, w *lookupWaiter) (*i2np.Message, error) {
	var flags byte = i2np.FlagRI
	if isLS2 {
		flags = i2np.FlagLS
	}
	tried := make(map[data.Hash]bool)
	exhausted := time.Time{} // set once no fresh untried floodfills remain

	for round := 0; ; round++ {
		peers := c.db.ClosestFloodfills(key, maxLookupPeers, tried)
		if len(peers) == 0 {
			// Nothing new to query. Chases may still deliver peers, so
			// only give up once they have drained and a grace window
			// (for replies already in flight) has passed.
			if c.chasesInFlight() == 0 {
				if exhausted.IsZero() {
					exhausted = c.now()
				}
				if c.now().Sub(exhausted) > stragglerGrace {
					return nil, fmt.Errorf("netdb: lookup for %s: no floodfills left", key.ToI2PBase64()[:8])
				}
			}
		} else {
			var who []string
			for _, ri := range peers {
				who = append(who, ri.RouterHash().ToI2PBase64()[:8])
			}
			c.logf("lookup %s round %d: querying %s", key.ToI2PBase64()[:8], round, strings.Join(who, " "))
			for _, ri := range peers {
				tried[ri.RouterHash()] = true
				lk := &i2np.DatabaseLookup{
					Key:   key,
					From:  c.db.OurHash,
					Flags: flags,
					Peers: excludedList(tried),
				}
				msg := i2np.New(i2np.TypeDatabaseLookup, lk.Payload())
				raw := msg.Encode9()
				h := ri.RouterHash()
				// The send may dial (an RI fetch, a proxy TCP connect, a
				// handshake — seconds each). Blocking the event loop on
				// it starves the reply channel: a reply that lands during
				// the send sits unconsumed until the context expires.
				// Send in the background; the select below keeps
				// re-selecting candidates while dials are in flight.
				go func() {
					if err := c.sender.SendI2NP(h, raw); err != nil {
						c.logf("lookup %s: send to %s: %v", key.ToI2PBase64()[:8], h.ToI2PBase64()[:8], err)
					}
				}()
			}
		}

		// Wait for an answer, a miss, or a tick to reselect candidates
		// (background RI fetches keep adding floodfills to the db).
		timer := time.NewTimer(reselectDelay)
	wait:
		for {
			select {
			case m := <-w.reply:
				timer.Stop()
				return m, nil
			case closer := <-w.miss:
				// Follow the pointers, but stay parked on the timer: an
				// immediate re-round on every miss hot-loops (hundreds
				// of lookups in seconds) — the chases are async anyway.
				c.chasePeers(closer, tried)
			case <-timer.C:
				break wait
			case <-ctx.Done():
				timer.Stop()
				// A reply may already be queued (it can land while this
				// loop is between rounds). Delivering it beats failing.
				select {
				case m := <-w.reply:
					return m, nil
				default:
				}
				return nil, fmt.Errorf("netdb: lookup for %s timed out", key.ToI2PBase64()[:8])
			}
		}
	}
}

// chasePeers kicks off background RI fetches for floodfills suggested
// by a DatabaseSearchReply, so a later selection round can query them.
// Deduplicated (the next miss re-suggests the same peers) and never
// blocking: a slow fetch only delays the next reselect, not the search.
func (c *LookupClient) chasePeers(peers []data.Hash, tried map[data.Hash]bool) {
	for _, h := range peers {
		if tried[h] || c.db.GetRI(h) != nil {
			continue
		}
		h := h
		c.chaseMu.Lock()
		c.chases++
		c.chaseMu.Unlock()
		go func() {
			defer func() {
				c.chaseMu.Lock()
				c.chases--
				c.chaseMu.Unlock()
			}()
			cctx, cancel := context.WithTimeout(context.Background(), chaseTimeout)
			defer cancel()
			if _, err := c.LookupRI(cctx, h); err != nil {
				c.logf("chase %s: %v", h.ToI2PBase64()[:8], err)
			}
		}()
	}
}

// chasesInFlight returns the number of background RI fetches running.
func (c *LookupClient) chasesInFlight() int {
	c.chaseMu.Lock()
	defer c.chaseMu.Unlock()
	return c.chases
}

// excludedList renders the tried set as the lookup's excluded-peer
// list (sorted for a stable wire format).
func excludedList(tried map[data.Hash]bool) []data.Hash {
	out := make([]data.Hash, 0, len(tried))
	for h := range tried {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToI2PBase64() < out[j].ToI2PBase64() })
	return out
}

// addWaiter registers interest in replies for a key. The first caller
// (the one that flips searching) owns the search; the rest join it.
func (c *LookupClient) addWaiter(key data.Hash, isLS2 bool) (w *lookupWaiter, p *pendingLookup, searcher bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p = c.pending[key]
	if p == nil {
		p = &pendingLookup{key: key, isLS2: isLS2, created: c.now(), done: make(chan struct{})}
		c.pending[key] = p
	}
	w = &lookupWaiter{
		reply: make(chan *i2np.Message, 1),
		miss:  make(chan []data.Hash, maxLookupPeers),
	}
	p.waiters = append(p.waiters, w)
	searcher = !p.searching
	if searcher {
		p.searching = true
		// A fresh generation: any prior done is closed, and the old
		// waiters select on their captured reference — reusing it would
		// wake them instantly against the new search.
		p.done = make(chan struct{})
	}
	return w, p, searcher
}

// endSearch marks the active search for a key as finished, closing its
// done channel to wake every joined waiter (which may then take the
// search over with their own remaining budget).
func (c *LookupClient) endSearch(key data.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[key]
	if p == nil || !p.searching {
		return
	}
	p.searching = false
	close(p.done)
}

// removeWaiter unregisters a waiter.
func (c *LookupClient) removeWaiter(key data.Hash, w *lookupWaiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[key]
	if p == nil {
		return
	}
	for i, x := range p.waiters {
		if x == w {
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
			c.logf("reply: bad store: %v", err)
			return false
		}
		c.logf("reply: store key %s kind %d", ds.Key.ToI2PBase64()[:8], ds.Kind)
		return c.dispatchReply(ds.Key, msg)
	case i2np.TypeDatabaseSearchReply:
		dsr, err := i2np.ParseDatabaseSearchReply(msg.Payload)
		if err != nil {
			return false
		}
		c.logf("reply: miss key %s peers %d", dsr.Key.ToI2PBase64()[:8], len(dsr.Peers))
		if os.Getenv("I2PGO_TRACE_DSR") != "" {
			for _, p := range dsr.Peers {
				c.logf("reply:   dsr peer %s", p.ToI2PBase64()[:12])
			}
		}
		return c.dispatchMiss(dsr.Key, dsr.Peers)
	}
	return false
}

// dispatchReply wakes the waiters for a key with the answer.
func (c *LookupClient) dispatchReply(key data.Hash, msg *i2np.Message) bool {
	c.mu.Lock()
	p := c.pending[key]
	n := 0
	if p != nil {
		n = len(p.waiters)
	}
	c.mu.Unlock()
	if p == nil {
		c.logf("reply: store key %s UNMATCHED (no pending lookup)", key.ToI2PBase64()[:8])
		return false
	}
	delivered := 0
	for _, w := range p.waiters {
		select {
		case w.reply <- msg:
			delivered++
		default:
		}
	}
	c.logf("reply: store key %s dispatched to %d/%d waiters", key.ToI2PBase64()[:8], delivered, n)
	return delivered > 0
}

// dispatchMiss wakes the waiters for a key with a search reply's
// closer floodfills. Returns false when nobody is waiting (the reply
// is then unconsumed).
func (c *LookupClient) dispatchMiss(key data.Hash, peers []data.Hash) bool {
	c.mu.Lock()
	p := c.pending[key]
	c.mu.Unlock()
	if p == nil {
		return false
	}
	for _, w := range p.waiters {
		select {
		case w.miss <- peers:
		default:
		}
	}
	return true
}

// logf emits a debug line when logging is enabled.
func (c *LookupClient) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log.Printf("netdb "+format, args...)
	}
}

// Package netdb implements the router-side network database: a local
// store of RouterInfos and LeaseSets, floodfill discovery, and lookup /
// store clients that speak DatabaseLookup / DatabaseStore /
// DatabaseSearchReply directly to floodfill routers over NTCP2.
//
// Our bootstrap strategy (before we have any tunnels): send lookups
// directly to floodfills over NTCP2 with no reply tunnel. Floodfills
// reply directly to the sender (HandleDatabaseLookupMessageJob sends
// the reply via SendMessageDirectJob when replyTunnel is null).
//
// Reference: FloodfillNetworkDatabaseFacade.java,
// HandleDatabaseLookupMessageJob.java, IterativeSearchJob.java.
package netdb

import (
	"crypto/sha256"
	"sort"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// NetDB is the local network database.
type NetDB struct {
	mu  sync.RWMutex
	ri  map[data.Hash]*data.RouterInfo
	ls2 map[data.Hash]*data.LeaseSet2

	// OurHash is our router hash (the "from" for lookups).
	OurHash data.Hash

	// Clock for tests.
	Now func() time.Time
}

// New creates an empty netdb.
func New(ourHash data.Hash) *NetDB {
	return &NetDB{
		ri:      make(map[data.Hash]*data.RouterInfo),
		ls2:     make(map[data.Hash]*data.LeaseSet2),
		OurHash: ourHash,
		Now:     time.Now,
	}
}

// StoreRI stores a router info (already parsed and verified).
func (n *NetDB) StoreRI(ri *data.RouterInfo) {
	if ri == nil {
		return
	}
	h := ri.RouterHash()
	n.mu.Lock()
	defer n.mu.Unlock()
	old, ok := n.ri[h]
	if ok && !old.Published.Before(ri.Published) {
		return // older or duplicate
	}
	n.ri[h] = ri
}

// GetRI returns the stored router info for hash, or nil.
func (n *NetDB) GetRI(h data.Hash) *data.RouterInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.ri[h]
}

// AllRouters returns every stored router info, freshest first.
func (n *NetDB) AllRouters() []*data.RouterInfo {
	n.mu.RLock()
	list := make([]*data.RouterInfo, 0, len(n.ri))
	for _, ri := range n.ri {
		list = append(list, ri)
	}
	n.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Published.After(list[j].Published) })
	return list
}

// StoreLS2 stores a LeaseSet2.
func (n *NetDB) StoreLS2(ls *data.LeaseSet2) {
	if ls == nil {
		return
	}
	h := data.DestinationHash(ls.Destination)
	n.mu.Lock()
	defer n.mu.Unlock()
	old, ok := n.ls2[h]
	if ok && !old.Published.Before(ls.Published) {
		return
	}
	n.ls2[h] = ls
}

// GetLS2 returns the stored LeaseSet2 for a destination hash, or nil.
func (n *NetDB) GetLS2(h data.Hash) *data.LeaseSet2 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.ls2[h]
}

// EvictLS2 drops the cached LeaseSet2 for a hash so the next lookup
// refetches it from the network (the cached copy may carry only
// expired leases even when recently published — tunnels rotate).
func (n *NetDB) EvictLS2(h data.Hash) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.ls2, h)
}

// AllLS2s returns every stored LeaseSet2.
func (n *NetDB) AllLS2s() []*data.LeaseSet2 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]*data.LeaseSet2, 0, len(n.ls2))
	for _, ls := range n.ls2 {
		out = append(out, ls)
	}
	return out
}

// Floodfills returns all known floodfill routers, freshest first.
// Reference: FloodfillPeerSelector.selectNearest (we only need the
// caps filter: routerInfo.getProperty("caps").contains("f")).
func (n *NetDB) Floodfills() []*data.RouterInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var out []*data.RouterInfo
	for _, ri := range n.ri {
		if !IsFloodfill(ri) {
			continue
		}
		// Skip very stale RIs: the floodfill may be long gone.
		if n.now().Sub(ri.Published) > riFreshness {
			continue
		}
		out = append(out, ri)
	}
	return out
}

// ClosestFloodfills returns up to want floodfill routers whose hashes
// are XOR-closest to key's routing key, skipping hashes in exclude.
// The routing key is SHA256(key || today-as-YYYYMMDD): the key space
// rotates daily to spread load. A floodfill stores the leasesets (and
// gets the stores) whose routing keys XOR-closest to its own hash, so
// a lookup must go to the closest floodfills, not just any.
// Reference: FloodfillPeerSelector.selectNearest + KH(key); i2pd
// CreateRoutingKey + GetClosestFloodfills.
func (n *NetDB) ClosestFloodfills(key data.Hash, want int, exclude map[data.Hash]bool) []*data.RouterInfo {
	rkey := routingKey(key, n.now())
	n.mu.RLock()
	var out []*data.RouterInfo
	for _, ri := range n.ri {
		if !IsFloodfill(ri) {
			continue
		}
		if n.now().Sub(ri.Published) > riFreshness {
			continue
		}
		h := ri.RouterHash()
		if exclude != nil && exclude[h] {
			continue
		}
		out = append(out, ri)
	}
	n.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		// Lexicographic compare of rkey^hash, the routing distance.
		var a, b [32]byte
		hi, hj := out[i].RouterHash(), out[j].RouterHash()
		for k := 0; k < 32; k++ {
			a[k] = rkey[k] ^ hi[k]
			b[k] = rkey[k] ^ hj[k]
		}
		for k := 0; k < 32; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	if len(out) > want {
		out = out[:want]
	}
	return out
}

// routingKey computes the daily Kademlia routing key of a hash:
// SHA256(hash || UTC date as YYYYMMDD). Reference: i2pd
// Identity.cpp CreateRoutingKey; Java KH(key).
func routingKey(h data.Hash, now time.Time) data.Hash {
	var buf [40]byte
	copy(buf[:32], h[:])
	// NB: the date must be copied in, not AppendFormat'ed — AppendFormat
	// appends to its argument, and buf[32:40] is already full (len == cap),
	// so the formatted date would land in a fresh allocation while buf's
	// tail stayed zero. That bug made every "routing key" a fixed
	// SHA256(hash || zeros), so searches queried the wrong floodfills
	// and starved for most destinations.
	copy(buf[32:40], now.UTC().Format("20060102"))
	return sha256.Sum256(buf[:])
}

// riFreshness is how long we trust an RI. The Java reference keeps
// routers for ROUTER_INFO_EXPIRATION = 27h (the same age the reseed
// bundles arrive at: 5-6h old is normal); reseeded RIs older than that
// are unlikely to still be running. Reference: KademliaNetworkDatabase-
// Facade.ROUTER_INFO_EXPIRATION.
const riFreshness = 27 * time.Hour

// IsFloodfill reports whether a router advertises floodfill caps.
func IsFloodfill(ri *data.RouterInfo) bool {
	if ri == nil {
		return false
	}
	caps := ri.Options["caps"]
	for _, c := range caps {
		if c == 'f' {
			return true
		}
	}
	return false
}

// now returns the clock.
func (n *NetDB) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

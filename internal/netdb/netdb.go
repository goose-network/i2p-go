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

// riFreshness is how long we trust an RI (publish interval is ~2h but
// we keep some slack). Reference: RouterInfo.PUBLISH_EXPIRATION.
const riFreshness = 3 * time.Hour

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

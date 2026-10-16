// NTCP2 connection management: dial floodfills and tunnel peers
// through the upstream proxy, cache connections by router hash, and
// dispatch inbound I2NP messages to the right layer.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/garlic"
	"github.com/goose-network/i2p-go/internal/i2np"
	"github.com/goose-network/i2p-go/internal/netdb"
	"github.com/goose-network/i2p-go/internal/ntcp2"
)

// dialTimeout bounds one NTCP2 connection attempt.
const dialTimeout = 15 * time.Second

// ErrNoRoute is returned when we cannot reach a router.
var ErrNoRoute = errors.New("router: no route to peer")

// SendI2NP implements netdb.Sender: it sends one raw NTCP2-format I2NP
// message to a router, dialing the connection when needed. A dead
// cached connection is dropped and dialed once more.
func (r *Router) SendI2NP(to data.Hash, raw []byte) error {
	c, err := r.Conn(to)
	if err != nil {
		return err
	}
	if err := c.SendI2NP(raw); err != nil {
		r.dropConn(to)
		c, err = r.Conn(to)
		if err != nil {
			return err
		}
		if err := c.SendI2NP(raw); err != nil {
			r.dropConn(to)
			return err
		}
	}
	return nil
}

// dropConn evicts a cached connection.
func (r *Router) dropConn(to data.Hash) {
	r.connMu.Lock()
	if c := r.conns[to]; c != nil {
		delete(r.conns, to)
		go c.Close(0)
	}
	r.connMu.Unlock()
}

// Conn returns a cached NTCP2 connection to a router hash, dialing if
// necessary. Connections whose read loop has ended are re-dialed.
func (r *Router) Conn(to data.Hash) (*ntcp2.Conn, error) {
	r.connMu.Lock()
	if c := r.conns[to]; c != nil && !c.Dead() {
		r.connMu.Unlock()
		return c, nil
	}
	r.connMu.Unlock()

	ri := r.db.GetRI(to)
	if ri == nil {
		// Try a lookup (bounded).
		ctx, cancel := context.WithTimeout(context.Background(), netdb.LookupTimeout)
		defer cancel()
		var err error
		ri, err = r.lookup.LookupRI(ctx, to)
		if err != nil {
			return nil, fmt.Errorf("router: RI for %s: %w", to.ToI2PBase64()[:8], err)
		}
	}
	return r.DialRI(ri)
}

// dialFailTTL is how long a failed NTCP2 dial poisons a router. Routers
// whose handshake consistently EOFs (measured on this network) would
// otherwise burn ~3s per dial — twice, with SendI2NP's retry — on every
// packet routed through their lease before failing over to another
// gateway. The TTL keeps the cache self-healing: a router that recovers
// is probed again within a minute.
const dialFailTTL = 60 * time.Second

// markDialFail remembers a failed dial for dialFailTTL.
func (r *Router) markDialFail(to data.Hash) {
	r.failMu.Lock()
	r.failUntil[to] = time.Now().Add(dialFailTTL)
	r.failMu.Unlock()
}

// dialFailed reports whether the router's dial is poisoned.
func (r *Router) dialFailed(to data.Hash) bool {
	r.failMu.Lock()
	defer r.failMu.Unlock()
	t, ok := r.failUntil[to]
	return ok && time.Now().Before(t)
}

// clearDialFail un-poisons a router after a successful dial.
func (r *Router) clearDialFail(to data.Hash) {
	r.failMu.Lock()
	delete(r.failUntil, to)
	r.failMu.Unlock()
}

// DialRI dials a router's NTCP2 address through the upstream proxy
// and performs the Alice handshake. On success the connection is
// cached and its read loop dispatches inbound messages.
func (r *Router) DialRI(ri *data.RouterInfo) (*ntcp2.Conn, error) {
	to := ri.RouterHash()
	r.connMu.Lock()
	if c := r.conns[to]; c != nil && !c.Dead() {
		r.connMu.Unlock()
		return c, nil
	}
	r.connMu.Unlock()
	// Recently failed: skip the dial entirely so the caller fails over
	// to another lease/gateway immediately instead of stalling on the
	// doomed handshake.
	if r.dialFailed(to) {
		return nil, ErrNoRoute
	}

	addr, cfg, err := r.ntcp2Config(ri)
	if err != nil {
		return nil, err
	}

	dctx, dcancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dcancel()
	var tcp net.Conn
	if host, _, err := net.SplitHostPort(addr); err == nil && isDirectDialHost(host) {
		// Loopback and RFC1918 addresses never need the upstream
		// proxy (and most SOCKS servers refuse to connect back to
		// them): dial direct.
		var nd net.Dialer
		tcp, err = nd.DialContext(dctx, "tcp", addr)
	} else if r.pd != nil {
		tcp, err = r.pd.Dial(dctx, "tcp", addr)
	} else {
		var nd net.Dialer
		tcp, err = nd.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		r.markDialFail(to)
		return nil, fmt.Errorf("router: dial %s: %w", addr, err)
	}

	c, err := ntcp2.HandshakeOutbound(tcp, cfg)
	if err != nil {
		tcp.Close()
		r.markDialFail(to)
		return nil, fmt.Errorf("router: ntcp2 handshake %s: %w", addr, err)
	}
	// A recovered router should be trusted again immediately.
	r.clearDialFail(to)
	// Bind the peer identity into the dispatch path (TunnelData must
	// be attributable to its sender for IBEP validation).
	from := ri.RouterHash()
	c.OnI2NP = func(raw []byte) { r.HandleI2NPFrom(from, raw) }
	c.OnRI = r.HandleRI
	// Evict on session death so the next send re-dials: a cached
	// dead conn silently swallows both sends (write error path) and
	// — worse — the peer's replies (TunnelData for our inbound
	// tunnels can only arrive on a live session; our published
	// address is deliberately undialable from outside).
	c.OnClose = func() {
		r.connMu.Lock()
		mine := r.conns[to] == c
		if mine {
			delete(r.conns, to)
		}
		r.connMu.Unlock()
		if mine {
			logf("ntcp2: session to %s ended: %s", to.ToI2PBase64()[:8], c.LastError)
		}
	}
	go c.ReadLoop()

	r.connMu.Lock()
	if old := r.conns[to]; old != nil {
		// Another dial won the race; use that one.
		r.connMu.Unlock()
		c.Close(0)
		return old, nil
	}
	r.conns[to] = c
	r.connMu.Unlock()
	return c, nil
}

// keepaliveLoop keeps every cached NTCP2 connection warm. The
// upstream proxy reaps connections after ~10-12s idle (measured:
// every session dies of EOF exactly 12s after establishment), which
// silently kills the sessions our inbound tunnels' data must ride
// on — TunnelData for our tunnels can only come back over a session
// we dialed, since our published address is deliberately undialable
// from outside. A DateTime block every 5s stays under the reaper;
// it is ~8 bytes/s of keepalive traffic per peer. The loop also
// re-dials the current inbound gateway when its session dropped:
// the proxy handshake is flaky, and one attempt per tick self-heals.
func (r *Router) keepaliveLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		r.connMu.Lock()
		snapshot := make(map[data.Hash]*ntcp2.Conn, len(r.conns))
		for k, v := range r.conns {
			snapshot[k] = v
		}
		r.connMu.Unlock()
		for to, c := range snapshot {
			if c.Dead() {
				continue
			}
			if err := c.Ping(); err != nil {
				r.dropConn(to)
			}
		}
		// Maintain a live session to the inbound tunnel's gateway:
		// responses to everything we send arrive as TunnelData
		// through it, and a dead gateway session means every reply
		// is dropped on the floor.
		if lease := r.Lease(); lease != nil {
			r.connMu.Lock()
			c := r.conns[lease.TunnelGW]
			r.connMu.Unlock()
			if c == nil || c.Dead() {
				if _, err := r.Conn(lease.TunnelGW); err != nil {
					logf("gateway session redial %s failed: %v", lease.TunnelGW.ToI2PBase64()[:8], err)
				} else {
					logf("gateway session redial %s ok", lease.TunnelGW.ToI2PBase64()[:8])
				}
			}
		}
	}
}

// isDirectDialHost reports whether a peer address should bypass the
// upstream SOCKS proxy: loopback and RFC1918 targets are local by
// definition, and proxies typically refuse them anyway. Hostnames are
// resolved first — an RI may publish a name (peers treat unparseable
// hosts as "unpublished" but still valid), and a name that resolves
// to a local address is still a local peer.
func isDirectDialHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
	}
	return false
}

// ntcp2Config extracts Bob's "s"/"i" options and builds the outbound
// handshake config.
func (r *Router) ntcp2Config(ri *data.RouterInfo) (addr string, cfg *ntcp2.OutboundConfig, err error) {
	var (
		s, i    string
		host    string
		portStr string
	)
	for _, a := range ri.Addresses {
		if a.TransportStyle != "NTCP2" {
			continue
		}
		if v := a.Options["v"]; v != "2" && len(v) > 0 && v[0] != '2' {
			continue
		}
		s = a.Options["s"]
		i = a.Options["i"]
		host = a.Options["host"]
		portStr = a.Options["port"]
		break
	}
	if s == "" || i == "" || host == "" || portStr == "" {
		return "", nil, fmt.Errorf("router: no NTCP2 address in RI %s", ri.RouterHash().ToI2PBase64()[:8])
	}
	// "s"/"i" are I2P-base64 encoded (Java net.i2p.data.Base64: the
	// "-~" alphabet, with padding).
	sk, err := data.DecodeI2PBase64(s)
	if err != nil || len(sk) != 32 {
		return "", nil, fmt.Errorf("router: bad s option")
	}
	iv, err := data.DecodeI2PBase64(i)
	if err != nil || len(iv) != 16 {
		return "", nil, fmt.Errorf("router: bad i option")
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 || port > 65535 {
		return "", nil, fmt.Errorf("router: bad port %q", portStr)
	}

	h := ri.RouterHash()
	cfg = &ntcp2.OutboundConfig{
		BobStatic:       *(*[32]byte)(sk),
		BobIV:           *(*[16]byte)(iv),
		BobRouterHash:   h[:],
		AliceStaticPriv: r.ntcpPriv[:],
		AliceRI:         r.ri.Bytes(),
		Network:         2,
	}
	return net.JoinHostPort(host, portStr), cfg, nil
}

// HandleI2NPFrom dispatches one raw (NTCP2-format) inbound I2NP
// message, attributing it to the sending router.
func (r *Router) HandleI2NPFrom(from data.Hash, raw []byte) {
	msg, err := i2np.Decode9(raw)
	if err != nil {
		return
	}
	logf("i2np <- %s: type %d len %d", from.ToI2PBase64()[:8], msg.Type, len(raw))
	switch msg.Type {
	case i2np.TypeDatabaseStore:
		r.HandleDatabaseStore(msg)
	case i2np.TypeDatabaseSearchReply:
		r.lookup.HandleReply(raw)
	case i2np.TypeDeliveryStatus:
		r.store.HandleDeliveryStatus(raw)
	case i2np.TypeShortTunnelBuild:
		r.HandleShortTunnelBuild(msg)
	case i2np.TypeTunnelData:
		r.HandleTunnelData(from, msg)
	default:
		// Deliver to lookup as a possible reply (stores arrive as
		// DatabaseStore, handled above; anything else is a no-op).
	}
}

// HandleDatabaseStore processes an inbound DatabaseStore: feed the
// lookup layer (a reply to our search), and store unknown RIs/LS2s.
func (r *Router) HandleDatabaseStore(msg *i2np.Message) {
	raw := msg.Encode9()
	// Reply to a pending lookup?
	if r.lookup.HandleReply(raw) {
		return
	}
	ds, err := i2np.ParseDatabaseStore(msg.Payload)
	if err != nil {
		return
	}
	switch ds.Kind {
	case i2np.DbRouterInfo:
		ri, err := data.ReadRouterInfo(ds.RouterInfo, true)
		if err == nil {
			r.db.StoreRI(&ri)
		}
	case i2np.DbLeaseSet2:
		ls, err := data.ReadLeaseSet2(ds.Entry, true)
		if err == nil {
			r.db.StoreLS2(ls)
		}
	}
}

// HandleRI stores RouterInfo blocks received from peers (netdb
// intake from the NTCP2 layer).
func (r *Router) HandleRI(raw []byte, flood bool) {
	ri, err := data.ReadRouterInfo(raw, true)
	if err == nil {
		r.db.StoreRI(&ri)
	}
}

// HandleTunnelData processes one TunnelData message from R (our
// inbound tunnel's IBGW): run the IBEP pipeline and dispatch any
// completed messages.
func (r *Router) HandleTunnelData(from data.Hash, msg *i2np.Message) {
	td, err := i2np.ParseTunnelData(msg.Payload)
	if err != nil {
		logf("tunnel data: parse: %v", err)
		return
	}
	r.tunMu.Lock()
	tun := r.tun
	if tun != nil && td.TunnelID != tun.IBEPTunnelID {
		tun = nil
	}
	r.tunMu.Unlock()
	if tun == nil {
		logf("tunnel data: no tunnel for ID %d (from %s)", td.TunnelID, from.ToI2PBase64()[:8])
		return
	}
	msgs, err := tun.HandleTunnelData(td, from)
	if err != nil {
		// Malformed or replayed: drop silently to keep the tunnel alive.
		logf("tunnel data: pipeline: %v", err)
		return
	}
	for _, m := range msgs {
		r.dispatchInbound(m)
	}
}

// dispatchInbound routes one message delivered out of our inbound
// tunnel: garlic for our client destination, store replies to the
// netdb layers.
func (r *Router) dispatchInbound(msg *i2np.Message) {
	switch msg.Type {
	case i2np.TypeGarlic:
		// The GarlicMessage body is a 4-byte length + the ECIES
		// ciphertext (Java GarlicMessage.readMessage strips the length;
		// decrypting the raw body skews every field by 4 bytes and fails
		// the MAC).
		gm, err := i2np.ParseGarlicMessage(msg.Payload)
		if err != nil {
			logf("garlic: bad garlic message: %v", err)
			return
		}
		cloves, err := r.garlic.DecryptMessage(gm.Data)
		if err != nil {
			logf("garlic: decrypt failed (%d bytes): %v", len(gm.Data), err)
			return
		}
		for _, cl := range cloves {
			r.dispatchClove(cl)
		}
	case i2np.TypeDatabaseStore:
		r.HandleDatabaseStore(msg)
	case i2np.TypeDatabaseSearchReply:
		r.lookup.HandleReply(msg.Encode9())
	case i2np.TypeDeliveryStatus:
		r.store.HandleDeliveryStatus(msg.Encode9())
	}
}

// dispatchClove handles one decrypted clove delivered to our
// destination.
func (r *Router) dispatchClove(cl *garlic.Clove) {
	if cl.Msg == nil {
		return
	}
	switch cl.Msg.Type {
	case i2np.TypeData:
		dm, err := i2np.ParseDataMessage(cl.Msg.Payload)
		if err != nil {
			logf("clove: bad data message: %v", err)
			return
		}
		r.stream.HandleMessage(dm.Data)
	default:
		// Other clove types (ack leaseset stores etc.) are not needed
		// for our client streams.
	}
}

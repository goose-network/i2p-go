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
// necessary.
func (r *Router) Conn(to data.Hash) (*ntcp2.Conn, error) {
	r.connMu.Lock()
	if c := r.conns[to]; c != nil {
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

// DialRI dials a router's NTCP2 address through the upstream proxy
// and performs the Alice handshake. On success the connection is
// cached and its read loop dispatches inbound messages.
func (r *Router) DialRI(ri *data.RouterInfo) (*ntcp2.Conn, error) {
	to := ri.RouterHash()
	r.connMu.Lock()
	if c := r.conns[to]; c != nil {
		r.connMu.Unlock()
		return c, nil
	}
	r.connMu.Unlock()

	addr, cfg, err := r.ntcp2Config(ri)
	if err != nil {
		return nil, err
	}

	dctx, dcancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dcancel()
	var tcp net.Conn
	if r.pd != nil {
		tcp, err = r.pd.Dial(dctx, "tcp", addr)
	} else {
		var nd net.Dialer
		tcp, err = nd.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("router: dial %s: %w", addr, err)
	}

	c, err := ntcp2.HandshakeOutbound(tcp, cfg)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("router: ntcp2 handshake %s: %w", addr, err)
	}
	// Bind the peer identity into the dispatch path (TunnelData must
	// be attributable to its sender for IBEP validation).
	from := ri.RouterHash()
	c.OnI2NP = func(raw []byte) { r.HandleI2NPFrom(from, raw) }
	c.OnRI = r.HandleRI
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
		return
	}
	r.tunMu.Lock()
	tun := r.tun
	if tun != nil && td.TunnelID != tun.IBEPTunnelID {
		tun = nil
	}
	r.tunMu.Unlock()
	if tun == nil {
		return
	}
	msgs, err := tun.HandleTunnelData(td, from)
	if err != nil {
		// Malformed or replayed: drop silently to keep the tunnel alive.
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
		cloves, err := r.garlic.DecryptMessage(msg.Payload)
		if err != nil {
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
			return
		}
		r.stream.HandleMessage(dm.Data)
	default:
		// Other clove types (ack leaseset stores etc.) are not needed
		// for our client streams.
	}
}

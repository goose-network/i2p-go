// Command i2p-go is a pure-Go I2P router that exposes a SOCKS5 proxy.
//
// Architecture (see internal/ packages for protocol details):
//
//   - All outbound TCP rides an upstream SOCKS5 proxy (NAT'd
//     environment); DNS is resolved remotely by the proxy.
//   - NTCP2 outbound only: we are always Alice, dialing routers from
//     our netdb. Bob stores our RI from handshake message 3, so no
//     separate RI publish is needed for routers we talk to.
//   - 0-hop outbound "tunnels": messages go directly to the target
//     router over NTCP2 (tunnel.SendDirect).
//   - 1-hop inbound tunnels: R (IBGW) forwards to us (IBEP) as
//     TunnelData; leases are published in our LeaseSet2.
//   - Netdb lookups/stores go directly to floodfills; replies come
//     back over the same NTCP2 connections.
//   - The client destination's streaming packets are garlic-wrapped
//     (ECIES-Ratchet, enc type 4) to the remote destination, riding
//     the remote LeaseSet2's inbound tunnel via its gateway.
//   - The SOCKS5 listener (internal/socks5) resolves .i2p names
//     (addressbook + netdb) and pumps bytes between the local TCP
//     connection and the I2P stream.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/garlic"
	"github.com/goose-network/i2p-go/internal/netdb"
	"github.com/goose-network/i2p-go/internal/ntcp2"
	"github.com/goose-network/i2p-go/internal/proxy"
	"github.com/goose-network/i2p-go/internal/reseed"
	"github.com/goose-network/i2p-go/internal/socks5"
	"github.com/goose-network/i2p-go/internal/streaming"
	"github.com/goose-network/i2p-go/internal/tunnel"
	"golang.org/x/crypto/curve25519"
)

// routerVersion mimics the Java router in the RI "coreVersion" option
// (matching the reference implementation avoids compatibility filters).
const routerVersion = "2.13.0"

func main() {
	var (
		socksAddr = flag.String("socks", "127.0.0.1:9050", "SOCKS5 proxy listen address")
		upstream  = flag.String("upstream", "127.0.0.1:7890", "upstream SOCKS5 proxy for outbound connections (empty = direct)")
		hostsFile = flag.String("hosts", "", "addressbook hosts.txt (name = base64 destination)")
		seedURL   = flag.String("seed", "", "reseed URL (default: try the known list)")
	)
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if err := run(*socksAddr, *upstream, *hostsFile, *seedURL); err != nil {
		log.Fatalf("i2p-go: %v", err)
	}
}

// run starts the router and blocks serving SOCKS5 until failure.
func run(socksAddr, upstream, hostsFile, seedURL string) error {
	ctx := context.Background()

	var pd *proxy.Dialer
	if upstream != "" {
		pd = &proxy.Dialer{Addr: upstream}
	}

	r, err := NewRouter(pd)
	if err != nil {
		return err
	}
	log.Printf("router %s up (b32 %s)", r.ri.RouterHash().ToI2PBase64()[:12], r.dest.Base32Address())

	// 1. Reseed if the netdb has no floodfills.
	if len(r.db.Floodfills()) == 0 {
		log.Printf("netdb empty: reseeding")
		urls := reseed.DefaultSeedURLs
		if seedURL != "" {
			urls = []string{seedURL}
		}
		su3, err := reseed.FetchAny(ctx, urls, pd)
		if err != nil {
			return fmt.Errorf("reseed: %w", err)
		}
		ris, err := su3.ExtractRouterInfos()
		if err != nil {
			return fmt.Errorf("reseed: %w", err)
		}
		nff := 0
		for _, ri := range ris {
			r.db.StoreRI(ri)
			if netdb.IsFloodfill(ri) {
				nff++
			}
		}
		log.Printf("reseed: %d routers (%d floodfills)", len(ris), nff)
	}

	// 2. Build one inbound tunnel through a non-floodfill router.
	if err := r.BuildInbound(ctx); err != nil {
		return fmt.Errorf("inbound tunnel: %w", err)
	}

	// 3. Publish our LeaseSet2 (our leases) to a floodfill.
	if err := r.PublishLeaseSet(ctx); err != nil {
		return fmt.Errorf("leaseset publish: %w", err)
	}

	// 4. Keep the tunnel alive.
	go r.rebuildLoop()

	// 5. Load the addressbook.
	if hostsFile != "" {
		if n, err := r.LoadHosts(hostsFile); err != nil {
			log.Printf("addressbook: %v", err)
		} else {
			log.Printf("addressbook: %d names", n)
		}
	}

	// 6. Serve SOCKS5.
	l, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 listening on %s", socksAddr)
	srv := &socks5.Server{Resolver: r, Dialer: r.stream}
	return srv.Serve(l)
}

// Router wires every layer together.
type Router struct {
	pd     *proxy.Dialer // upstream SOCKS5 dialer (nil = direct)
	db     *netdb.NetDB
	lookup *netdb.LookupClient
	store  *netdb.StoreClient

	// Router identity (RI) keys.
	signPriv ed25519.PrivateKey
	ntcpPriv [32]byte // NTCP2 static X25519
	ri       *data.RouterInfo

	// Client destination.
	dest     *data.Destination
	destPriv ed25519.PrivateKey
	garlic   *garlic.Manager
	stream   *streaming.Manager

	// Inbound tunnel state.
	tunMu sync.Mutex
	tun   *tunnel.InboundTunnel
	tunB  map[uint32]*pendingBuild // by reply message ID

	// NTCP2 connection cache.
	connMu sync.Mutex
	conns  map[data.Hash]*ntcp2.Conn

	// Addressbook.
	hostMu sync.Mutex
	hosts  map[string]*data.Destination
}

// NewRouter generates all identities and wires the layers.
func NewRouter(pd *proxy.Dialer) (*Router, error) {
	// Router signing identity.
	_, sp, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// NTCP2 static key.
	var np [32]byte
	if _, err := rand.Read(np[:]); err != nil {
		return nil, err
	}
	// Client destination signing key.
	_, dp, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// Client garlic (ratchet) key.
	var gp [32]byte
	if _, err := rand.Read(gp[:]); err != nil {
		return nil, err
	}
	gm, err := garlic.NewManager(gp[:])
	if err != nil {
		return nil, err
	}

	r := &Router{
		pd:       pd,
		signPriv: sp,
		ntcpPriv: np,
		destPriv: dp,
		garlic:   gm,
		tunB:     make(map[uint32]*pendingBuild),
		conns:    make(map[data.Hash]*ntcp2.Conn),
		hosts:    make(map[string]*data.Destination),
	}

	// Client destination: Ed25519 + ECIES-Ratchet (enc type 4).
	r.dest = &data.Destination{
		EncKey:     gm.PublicKey(),
		SigningKey: dp.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}

	// Router identity: X25519 encryption key (same key as NTCP2 "s"),
	// Ed25519 signing key.
	npub, err := curve25519.X25519(np[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	ident := data.RouterIdentity{
		EncKey:     npub,
		SigningKey: sp.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	r.db = netdb.New(ident.RouterHash())
	r.lookup = netdb.NewLookupClient(r.db, r)
	r.store = netdb.NewStoreClient(r.db, r)

	ri, err := buildRouterInfo(ident, sp, npub)
	if err != nil {
		return nil, err
	}
	r.ri = ri

	// Streaming over the garlic send path.
	r.stream = streaming.NewManager(r.dest, dp, r, streaming.Options{})
	return r, nil
}

// buildRouterInfo creates our signed RouterInfo with an NTCP2 address.
// The address carries a hostname, not an IP: Bob's IP-mismatch ban
// (InboundEstablishState.gotRI) only triggers when the published
// address parses as an IP literal different from the actual source IP
// — a hostname can't mismatch, which is what a proxy-routed router
// needs (the TCP source is the proxy's or NAT's, not ours).
func buildRouterInfo(ident data.RouterIdentity, sp ed25519.PrivateKey, ntpub []byte) (*data.RouterInfo, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	addr := data.RouterAddress{
		Cost:           5,
		Expiration:     time.Time{},
		TransportStyle: "NTCP2",
		Options: map[string]string{
			"host": "proxy.i2p-go.invalid",
			"port": "0",
			"s":    data.EncodeToI2PBase64(ntpub),
			"v":    "2",
			"i":    data.EncodeToI2PBase64(iv),
			"padd": "1",
			"padl": "1",
		},
	}
	ri := &data.RouterInfo{
		Identity:  ident,
		Published: time.Now(),
		Addresses: []data.RouterAddress{addr},
		Options: map[string]string{
			"caps":           "LU", // low bandwidth, unreachable (we don't accept inbound)
			"router.version": routerVersion,
			"netId":          "2",
		},
	}
	if err := ri.Sign(sp); err != nil {
		return nil, err
	}
	return ri, nil
}

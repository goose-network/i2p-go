// Inbound tunnel management: build a 1-hop tunnel through a non-
// floodfill router, keep it alive, and publish its lease.
//
// The build reply arrives asynchronously as an inbound STBM (I2NP type
// 25) whose message ID is our ReplyMessageID; pendingBuild bridges the
// async HandleI2NP dispatch to the synchronous BuildInbound caller.
package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
	"github.com/goose-network/i2p-go/internal/netdb"
	"github.com/goose-network/i2p-go/internal/tunnel"
)

// pendingBuild is one outstanding tunnel build.
type pendingBuild struct {
	build *tunnel.InboundBuild
	ch    chan *tunnel.InboundTunnel
}

// Finish resolves a pending build from an inbound reply STBM.
func (p *pendingBuild) Finish(reply *i2np.Message) {
	tun, _, err := p.build.Resolve(reply)
	if err != nil || tun == nil {
		return // rejected or malformed: leave the waiter to time out
	}
	select {
	case p.ch <- tun:
	default:
	}
}

// tunnelCandidates picks routers to build inbound tunnels through. The
// hop is also the gateway published in our LeaseSet2's lease: remote
// senders deliver reply garlic to it as a TunnelGatewayMessage, so it
// must be publicly reachable — a NAT'd or loopback gateway strands
// every reply (senders cannot even connect to deliver). Routers with
// a public NTCP2 address and "reachable" caps are preferred; routers
// without them are kept as last resort. Floodfills are avoided as
// tunnel peers (they carry netdb traffic, not client tunnels —
// reference: TunnelPeerBuilder).
func (r *Router) tunnelCandidates(n int) []*data.RouterInfo {
	var reach, pub, rest []*data.RouterInfo
	for _, ri := range r.db.AllRouters() {
		if netdb.IsFloodfill(ri) {
			continue
		}
		if ri.Options["caps"] == "LU" {
			continue
		}
		if !hasNTCP2(ri) {
			continue
		}
		switch {
		case isPublicRouter(ri) && strings.Contains(ri.Options["caps"], "U"):
			reach = append(reach, ri)
		case isPublicRouter(ri):
			pub = append(pub, ri)
		default:
			rest = append(rest, ri)
		}
	}
	out := append(append(reach, pub...), rest...)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// isPublicRouter reports whether the router's NTCP2 address is a
// public IP literal (routable from anywhere).
func isPublicRouter(ri *data.RouterInfo) bool {
	for _, a := range ri.Addresses {
		if a.TransportStyle != "NTCP2" {
			continue
		}
		host := a.Options["host"]
		ip := net.ParseIP(host)
		if ip == nil {
			continue // hostname or placeholder: not directly routable
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
			continue // CGNAT 100.64.0.0/10
		}
		return true
	}
	return false
}

// hasNTCP2 checks the RI for a usable NTCP2 address.
func hasNTCP2(ri *data.RouterInfo) bool {
	for _, a := range ri.Addresses {
		if a.TransportStyle != "NTCP2" {
			continue
		}
		if a.Options["s"] != "" && a.Options["i"] != "" && a.Options["host"] != "" && a.Options["port"] != "" {
			return true
		}
	}
	return false
}

// BuildInbound creates a fresh 1-hop inbound tunnel (tearing down any
// existing one).
func (r *Router) BuildInbound(ctx context.Context) error {
	cands := r.tunnelCandidates(4)
	var lastErr error
	for _, ri := range cands {
		ourHash := r.ri.RouterHash()
		stbm, build, err := tunnel.BuildInbound(ri, ourHash, time.Now())
		if err != nil {
			lastErr = err
			continue
		}
		pb := &pendingBuild{build: build, ch: make(chan *tunnel.InboundTunnel, 1)}
		r.tunMu.Lock()
		r.tunB[build.ReplyMessageID()] = pb
		r.tunMu.Unlock()

		if err := r.SendI2NP(ri.RouterHash(), stbm.Encode9()); err != nil {
			r.tunMu.Lock()
			delete(r.tunB, build.ReplyMessageID())
			r.tunMu.Unlock()
			lastErr = fmt.Errorf("send STBM to %s: %w", ri.RouterHash().ToI2PBase64()[:8], err)
			continue
		}

		wctx, cancel := context.WithTimeout(ctx, tunnel.TunnelBuildTimeout)
		tun := r.waitBuild(pb, wctx)
		cancel()
		r.tunMu.Lock()
		delete(r.tunB, build.ReplyMessageID())
		r.tunMu.Unlock()
		if tun == nil {
			lastErr = fmt.Errorf("build through %s got no reply", ri.RouterHash().ToI2PBase64()[:8])
			continue
		}
		r.tun = tun
		logf("inbound tunnel up: R=%s gwID=%d (expires %s)",
			tun.RHash.ToI2PBase64()[:8], tun.RTunnelID, tun.Expiration.Format("15:04:05"))
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no tunnel candidates")
	}
	return lastErr
}

// waitBuild blocks until the pending build resolves, times out, or
// the build expires.
func (r *Router) waitBuild(pb *pendingBuild, ctx context.Context) *tunnel.InboundTunnel {
	for {
		select {
		case <-ctx.Done():
			return nil
		case tun := <-pb.ch:
			return tun
		case <-time.After(200 * time.Millisecond):
			if pb.build.Expired(time.Now()) {
				return nil
			}
		}
	}
}

// HandleShortTunnelBuild matches an inbound mutated STBM against a
// pending build and resolves it.
func (r *Router) HandleShortTunnelBuild(msg *i2np.Message) {
	r.tunMu.Lock()
	pb := r.tunB[msg.ID]
	r.tunMu.Unlock()
	if pb == nil {
		return
	}
	pb.Finish(msg)
}

// rebuildLoop replaces the live tunnel before it expires (tunnels
// live 10 minutes; rebuild at 8).
func (r *Router) rebuildLoop() {
	for {
		lease := r.Lease()
		if lease == nil {
			time.Sleep(30 * time.Second)
			continue
		}
		d := time.Until(lease.ExpiresOn.Add(-2 * time.Minute))
		if d < 0 {
			d = 0
		}
		time.Sleep(d)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := r.BuildInbound(ctx); err != nil {
			logf("inbound tunnel rebuild failed: %v", err)
			cancel()
			continue
		}
		// Republish the LeaseSet2 with the new lease; a store failure
		// (unreachable floodfills) is retried after a minute — without
		// a published lease, no remote can route replies back to us.
		for try := 1; ; try++ {
			if err := r.PublishLeaseSet(ctx); err != nil {
				logf("leaseset republish failed (try %d): %v", try, err)
				select {
				case <-time.After(time.Minute):
					continue
				case <-ctx.Done():
				}
			}
			break
		}
		cancel()
	}
}

// Lease returns the current lease, or nil when no live tunnel exists.
func (r *Router) Lease() *tunnel.Lease {
	r.tunMu.Lock()
	defer r.tunMu.Unlock()
	if r.tun == nil || r.tun.Expired(time.Now()) {
		return nil
	}
	return &tunnel.Lease{
		TunnelGW:  r.tun.RHash,
		TunnelID:  r.tun.RTunnelID,
		ExpiresOn: r.tun.Expiration,
	}
}

// logf is the local logger.
func logf(format string, args ...any) {
	fmt.Printf("[%s] "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, args...)...)
}

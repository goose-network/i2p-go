// The client layer: addressbook + netdb resolution for SOCKS5, the
// LeaseSet2 we publish for our destination, and the garlic send path
// that streaming rides.
//
// Outbound path (reference: OutboundClientMessageOneShotJob +
// GarlicMessageBuilder.buildECIESMessage):
//
//	streaming packet -> CompressPayload (I2CP gz format, proto/ports
//	in the gzip header) -> DataMessage -> clove with delivery mode
//	DESTINATION (the remote destination hash) -> ECIES-Ratchet encrypt
//	to the remote LS2's enc-type-4 key -> GarlicMessage -> tunnel.
//	SendDirect wraps it in a TunnelGatewayMessage for the remote
//	lease's gateway, sent to that router over NTCP2.
package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/garlic"
	"github.com/goose-network/i2p-go/internal/i2np"
	"github.com/goose-network/i2p-go/internal/streaming"
	"github.com/goose-network/i2p-go/internal/tunnel"
)

// lookupTimeout bounds destination lookups for SOCKS5 requests.
const lookupTimeout = 75 * time.Second

// LookupDestination implements socks5.Resolver: addressbook names,
// plain .b32.i2p via netdb LS2 lookup.
func (r *Router) LookupDestination(ctx context.Context, host string) (*data.Destination, error) {
	// Addressbook first.
	r.hostMu.Lock()
	dest := r.hosts[strings.ToLower(host)]
	r.hostMu.Unlock()
	if dest != nil {
		return dest, nil
	}

	// Plain b32: the 52-char base32 of the destination hash.
	if plain, _ := isB32(host); plain {
		ls, lerr := r.lookup.LookupLS2(ctx, b32ToHash(host))
		if lerr != nil {
			return nil, lerr
		}
		return &ls.Destination, nil
	}
	return nil, nil // unknown name: Java replies "host unreachable"
}

// isB32 checks for a .b32.i2p(/.alt) host (mirrors socks5.isB32Host).
func isB32(host string) (plain, blinded bool) {
	lc := strings.ToLower(host)
	for _, suffix := range []string{".b32.i2p", ".b32.i2p.alt"} {
		if strings.HasSuffix(lc, suffix) {
			prefix := lc[:len(lc)-len(suffix)]
			return len(prefix) == 52, len(prefix) > 52
		}
	}
	return false, false
}

// b32ToHash decodes the 52-char base32 prefix into a destination hash.
func b32ToHash(host string) data.Hash {
	lc := strings.ToLower(host)
	for _, suffix := range []string{".b32.i2p", ".b32.i2p.alt"} {
		if strings.HasSuffix(lc, suffix) {
			lc = lc[:len(lc)-len(suffix)]
			break
		}
	}
	var h data.Hash
	b, err := data.DecodeI2PBase32(lc)
	if err == nil {
		copy(h[:], b)
	}
	return h
}

// LoadHosts reads a hosts.txt addressbook: lines of
// "name=base64destination".
func (r *Router) LoadHosts(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024) // destinations are ~700 bytes
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some hosts.txt formats are "host = dest"; handle both.
		eq := strings.IndexAny(line, "=\t")
		if eq < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		if name == "" || len(val) < 516 {
			continue
		}
		raw, err := data.DecodeI2PBase64(val)
		if err != nil {
			continue
		}
		dest, _, err := data.ReadDestination(raw)
		if err != nil {
			continue
		}
		r.hostMu.Lock()
		r.hosts[name] = &dest
		r.hostMu.Unlock()
		n++
	}
	return n, sc.Err()
}

// PublishLeaseSet builds and signs our LeaseSet2 with the current
// inbound tunnel lease, then stores it to a floodfill and waits for
// the delivery-status confirmation.
func (r *Router) PublishLeaseSet(ctx context.Context) error {
	lease := r.Lease()
	if lease == nil {
		return errNoTunnel
	}
	ls := &data.LeaseSet2{
		Destination: *r.dest,
		Published:   time.Now(),
		Expires:     time.Now().Add(10 * time.Minute),
		EncryptionKeys: []data.PublicKey{
			{EncType: data.EncECIES_X25519, Key: r.garlic.PublicKey()},
		},
		Leases: []data.Lease{
			{
				Gateway:  lease.TunnelGW,
				TunnelID: lease.TunnelID,
				End:      lease.ExpiresOn,
			},
		},
	}
	if err := ls.Sign(r.destPriv); err != nil {
		return err
	}
	if err := r.store.StoreLS2(ctx, ls); err != nil {
		return err
	}
	r.db.StoreLS2(ls) // our own copy for local reference
	logf("leaseset published (%d lease, enc ECIES-X25519)", len(ls.Leases))
	return nil
}

// errNoTunnel is set when no inbound tunnel exists.
var errNoTunnel = errors.New("router: no inbound tunnel")

// SendPacket implements streaming.PacketSender: the full outbound
// garlic path for one streaming packet.
func (r *Router) SendPacket(to *data.Destination, packet []byte, fromPort, toPort uint16) error {
	remoteHash := data.DestinationHash(*to)

	// Remote LS2: ratchet key + inbound tunnel lease.
	ls, err := r.remoteLeaseSet(to)
	if err != nil {
		return err
	}

	// I2CP payload: gzip with proto/ports in the header.
	gz, err := streaming.CompressPayload(packet, streaming.ProtoStreaming, fromPort, toPort)
	if err != nil {
		return err
	}

	// DataMessage clove, destination delivery mode.
	dm := &i2np.DataMessage{Data: gz}
	clove := &garlic.Clove{
		Instructions: garlic.DeliveryInstructions{
			Mode:            garlic.ModeDestination,
			DestinationHash: remoteHash[:],
		},
		Msg: i2np.New(i2np.TypeData, dm.Payload()),
	}

	// Garlic: ECIES-Ratchet to the remote ratchet public key.
	ct := r.garlic.EncryptSession(lsRatchetKey(ls), []*garlic.Clove{clove})
	gmsg := i2np.New(i2np.TypeGarlic, (&i2np.GarlicMessage{Data: ct}).Payload())

	// Route through the remote lease: TunnelGatewayMessage to the
	// remote tunnel gateway, sent over NTCP2.
	lease := pickLease(ls)
	if lease == nil {
		return errNoLease
	}
	wrapped := tunnel.SendDirect(gmsg, lease.TunnelID)
	return r.SendI2NP(lease.Gateway, wrapped.Encode9())
}

// remoteLeaseSet looks up (and caches) the remote LeaseSet2.
func (r *Router) remoteLeaseSet(to *data.Destination) (*data.LeaseSet2, error) {
	hash := data.DestinationHash(*to)
	if ls := r.db.GetLS2(hash); ls != nil && time.Since(ls.Published) < lsFreshness {
		return ls, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return r.lookup.LookupLS2(ctx, hash)
}

// lsFreshness is how long we trust a remote LS2 before re-looking.
const lsFreshness = 3 * time.Minute

// lsRatchetKey extracts the enc-type-4 (ECIES-Ratchet) key.
func lsRatchetKey(ls *data.LeaseSet2) []byte {
	for _, k := range ls.EncryptionKeys {
		if k.EncType == data.EncECIES_X25519 && !k.ElGamal {
			return k.Key
		}
	}
	return nil
}

// errNoLease is set when the remote LS2 has no usable lease.
var errNoLease = errors.New("router: remote has no lease")

// pickLease chooses the freshest non-expired lease.
func pickLease(ls *data.LeaseSet2) *data.Lease {
	now := time.Now()
	var best *data.Lease
	for i := range ls.Leases {
		l := &ls.Leases[i]
		if l.End.Before(now) {
			continue
		}
		if best == nil || l.End.After(best.End) {
			best = l
		}
	}
	return best
}

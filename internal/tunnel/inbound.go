// The inbound tunnel: our 1-hop tunnels [R = IBGW, we = IBEP].
//
// Data path (R = the IBGW, we = the IBEP):
//
//	remote peer --TGM(RTunnelID)--> R --TunnelData(IBEPTunnelID)--> us
//
// R preprocesses (TrivialPreprocessor) and layer-encrypts (IBGW
// HopProcessor.process) each 1024-byte block; we run the inbound
// endpoint pipeline on arrival: sender check, IV replay validation,
// per-hop decryption (LayerDecrypt with R's keys — for a 1-hop tunnel
// that is exactly one hop, loop length-2..0 = hop 0), preprocessed
// verification, fragment reassembly, and local delivery of complete
// I2NP messages.
//
// Reference: InboundEndpointProcessor.java,
// InboundGatewayReceiver.java, FragmentHandler.java,
// TunnelDispatcher.java.
package tunnel

import (
	"fmt"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// TunnelBuildTimeout is how long we wait for a build reply.
// Reference: BuildRequestor.REQUEST_TIMEOUT.
const TunnelBuildTimeout = 30 * time.Second

// InboundTunnel is a live 1-hop inbound tunnel we created.
type InboundTunnel struct {
	// RHash is the IBGW (R)'s router hash. LeaseSet2 leases published
	// for this tunnel are (RHash, RTunnelID).
	RHash data.Hash
	// RTunnelID is the tunnel ID R receives on: the ID remote routers
	// put in TunnelGateway messages sent to R for this tunnel, and the
	// tunnel ID we publish in leases.
	RTunnelID uint32
	// IBEPTunnelID is the tunnel ID we receive on: the ID R puts in
	// TunnelData messages sent to us.
	IBEPTunnelID uint32
	// RKeys are R's derived keys: LayerKey/IVKey for IBEP decryption.
	RKeys *HopKeys

	Created     time.Time
	Expiration  time.Time
	validator   *IVValidator
	reassembler *Reassembler
}

// BuildInbound starts a 1-hop inbound tunnel build through R. It
// returns the STBM to send directly to R and the pending build, which
// Resolve turns into a live tunnel when the reply arrives.
// Reference: BuildRequestor.buildTunnel (STBM branch).
func BuildInbound(ri *data.RouterInfo, ourHash data.Hash, now time.Time) (*i2np.Message, *InboundBuild, error) {
	replyID := randomTunnelID()
	state, err := newInboundBuild(ri, replyID, now)
	if err != nil {
		return nil, nil, err
	}
	msg, err := state.encodeSTBM(ourHash)
	if err != nil {
		return nil, nil, err
	}
	return msg, &InboundBuild{state: state, started: now}, nil
}

// InboundBuild is a pending 1-hop inbound tunnel build.
type InboundBuild struct {
	state   *inboundBuildState
	started time.Time
}

// ReplyMessageID is the ID R's reply STBM carries.
func (b *InboundBuild) ReplyMessageID() uint32 { return b.state.ReplyMessageID }

// RHash is the IBGW's router hash.
func (b *InboundBuild) RHash() data.Hash { return b.state.RHash }

// Expired reports whether the build has waited too long.
func (b *InboundBuild) Expired(now time.Time) bool {
	return now.Sub(b.started) > TunnelBuildTimeout
}

// Resolve processes the mutated STBM R sent back. On acceptance it
// returns the live tunnel.
func (b *InboundBuild) Resolve(reply *i2np.Message) (*InboundTunnel, *BuildResult, error) {
	result, err := b.state.ParseBuildReply(reply)
	if err != nil {
		return nil, nil, err
	}
	if !result.Accepted {
		return nil, result, nil
	}
	s := b.state
	t := &InboundTunnel{
		RHash:        s.RHash,
		RTunnelID:    s.RTunnelID,
		IBEPTunnelID: s.IBEPTunnelID,
		RKeys:        s.RKeys,
		Created:      b.started,
		Expiration:   b.started.Add(buildExpirationSeconds * time.Second),
		validator:    NewIVValidator(),
		reassembler:  NewReassembler(),
	}
	return t, result, nil
}

// HandleTunnelData runs the inbound endpoint pipeline on one TunnelData
// message from R and returns any I2NP messages completed by it.
// Reference: InboundEndpointProcessor.retrievePreprocessedData +
// FragmentHandler.receiveTunnelMessage.
func (t *InboundTunnel) HandleTunnelData(td *i2np.TunnelData, from data.Hash) ([]*i2np.Message, error) {
	if from != t.RHash {
		return nil, fmt.Errorf("tunnel: data from %s, expected %s", from, t.RHash)
	}
	if td.TunnelID != t.IBEPTunnelID {
		return nil, fmt.Errorf("tunnel: data for ID %d, expected %d", td.TunnelID, t.IBEPTunnelID)
	}
	// Replay check on the wire bytes (before decryption).
	if !t.validator.ReceiveIV(td.Data) {
		return nil, fmt.Errorf("tunnel: replayed IV")
	}
	// Undo R's layer encryption (the only hop before the endpoint).
	if err := LayerDecrypt(td.Data, t.RKeys.LayerKey, t.RKeys.IVKey); err != nil {
		return nil, err
	}
	// Verify the preprocessed structure and parse the fragments.
	frags, err := VerifyAndParse(td.Data)
	if err != nil {
		return nil, err
	}
	// Reassemble and deliver complete messages.
	var out []*i2np.Message
	for _, f := range frags {
		cm, err := t.reassembler.Receive(f)
		if err != nil {
			continue // malformed fragment: drop it, keep the tunnel alive
		}
		if cm == nil {
			continue
		}
		msg, err := i2np.Decode16(cm.Data)
		if err != nil {
			continue
		}
		out = append(out, msg)
	}
	return out, nil
}

// Expired reports whether the tunnel should be rebuilt.
func (t *InboundTunnel) Expired(now time.Time) bool { return now.After(t.Expiration) }

// Lease is the published lease for this tunnel: (R, RTunnelID).
type Lease struct {
	TunnelGW  data.Hash
	TunnelID  uint32
	ExpiresOn time.Time
}

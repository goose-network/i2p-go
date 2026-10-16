// The outbound side: our outbound "tunnels" are 0-hop — every message
// is sent directly to its target router over NTCP2. This is the
// TunnelGatewayZeroHop + OutboundMessageDistributor behavior: no
// preprocessing, no layer crypto, no build. If the target is an
// inbound-tunnel gateway (toTunnel set), the message rides inside a
// TunnelGatewayMessage addressed to that router; otherwise it is a
// plain direct I2NP message.
//
// Reference: TunnelGatewayZeroHop.java,
// OutboundMessageDistributor.distribute.
package tunnel

import (
	"github.com/goose-network/i2p-go/internal/i2np"
)

// SendDirect builds the I2NP message to transmit for a 0-hop outbound
// send. toTunnel != 0 means the target router is the gateway of an
// inbound tunnel (ours or a peer's) and msg must be wrapped in a
// TunnelGatewayMessage carrying that tunnel ID; the returned message is
// addressed to that router. Otherwise the message itself is returned,
// addressed to toRouter.
// Reference: OutboundMessageDistributor.distribute (tunnel != null
// branch).
func SendDirect(msg *i2np.Message, toTunnel uint32) *i2np.Message {
	if toTunnel == 0 {
		return msg
	}
	tg := &i2np.TunnelGateway{
		TunnelID: toTunnel,
		Message:  msg.Encode16(),
	}
	out := i2np.New(i2np.TypeTunnelGateway, tg.Payload())
	out.ID = msg.ID
	out.Expiration = msg.Expiration
	return out
}

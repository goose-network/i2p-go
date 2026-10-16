// Garlic cloves in the ECIES-Ratchet short format: DeliveryInstructions
// followed by an I2NP message in the NTCP2 raw form (9-byte header: type,
// 4-byte ID, 4-byte expiration in seconds, then the body). No clove ID,
// no separate expiration, no certificate — the message header supplies
// all three. Reference: GarlicClove.java readBytesRatchet/
// writeBytesRatchet and DeliveryInstructions.java.
package garlic

import (
	"encoding/binary"
	"fmt"

	"github.com/goose-network/i2p-go/internal/i2np"
)

// Delivery instruction modes (bits 5-6 of the flag byte).
// Reference: DeliveryInstructions.java FLAG_MODE_*.
const (
	ModeLocal       = 0
	ModeDestination = 1
	ModeRouter      = 2
	ModeTunnel      = 3
)

// flagDelay is the unused delay-requested flag. Reference:
// DeliveryInstructions.java FLAG_DELAY.
const flagDelay = 16

// DeliveryInstructions is the clove routing instruction set. Only
// the mode is used on modern wire format; encrypted/delay are never
// sent. Reference: DeliveryInstructions.java.
type DeliveryInstructions struct {
	Mode            int    // 0-3
	DestinationHash []byte // 32 bytes, ModeDestination
	RouterHash      []byte // 32 bytes, ModeRouter/ModeTunnel
	TunnelID        uint32 // ModeTunnel
	DelayRequested  bool
	DelaySeconds    uint32
}

// Encode writes the instructions. Reference:
// DeliveryInstructions.writeBytes.
func (di *DeliveryInstructions) Encode() []byte {
	var flags byte
	switch di.Mode {
	case ModeLocal:
	case ModeDestination:
		flags = ModeDestination << 5
	case ModeRouter:
		flags = ModeRouter << 5
	case ModeTunnel:
		flags = ModeTunnel << 5
	}
	if di.DelayRequested {
		flags |= flagDelay
	}
	out := []byte{flags}
	switch di.Mode {
	case ModeDestination:
		out = append(out, di.DestinationHash...)
	case ModeRouter:
		out = append(out, di.RouterHash...)
	case ModeTunnel:
		out = append(out, di.RouterHash...)
		var tid [4]byte
		binary.BigEndian.PutUint32(tid[:], di.TunnelID)
		out = append(out, tid[:]...)
	}
	if di.DelayRequested {
		var d [4]byte
		binary.BigEndian.PutUint32(d[:], di.DelaySeconds)
		out = append(out, d[:]...)
	}
	return out
}

// Size is the encoded length. Reference: DeliveryInstructions.getSize.
func (di *DeliveryInstructions) Size() int { return len(di.Encode()) }

// DecodeDeliveryInstructions parses instructions from data.
// Reference: DeliveryInstructions.create + readBytes.
func DecodeDeliveryInstructions(data []byte) (*DeliveryInstructions, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("garlic: empty instructions")
	}
	flags := data[0]
	di := &DeliveryInstructions{Mode: int(flags >> 5 & 0x03)}
	off := 1
	switch di.Mode {
	case ModeLocal:
	case ModeDestination:
		if len(data)-off < 32 {
			return nil, 0, fmt.Errorf("garlic: short destination hash")
		}
		di.DestinationHash = append([]byte(nil), data[off:off+32]...)
		off += 32
	case ModeRouter:
		if len(data)-off < 32 {
			return nil, 0, fmt.Errorf("garlic: short router hash")
		}
		di.RouterHash = append([]byte(nil), data[off:off+32]...)
		off += 32
	case ModeTunnel:
		if len(data)-off < 36 {
			return nil, 0, fmt.Errorf("garlic: short tunnel instructions")
		}
		di.RouterHash = append([]byte(nil), data[off:off+32]...)
		di.TunnelID = binary.BigEndian.Uint32(data[off+32 : off+36])
		off += 36
	}
	if flags&flagDelay != 0 {
		if len(data)-off < 4 {
			return nil, 0, fmt.Errorf("garlic: short delay")
		}
		di.DelayRequested = true
		di.DelaySeconds = binary.BigEndian.Uint32(data[off : off+4])
		off += 4
	}
	return di, off, nil
}

// Clove is one garlic clove in the ratchet short format.
type Clove struct {
	Instructions DeliveryInstructions
	Msg          *i2np.Message
}

// EncodeRatchet serializes the clove: instructions + NTCP2-style
// message. Reference: GarlicClove.writeBytesRatchet.
func (c *Clove) EncodeRatchet() []byte {
	out := c.Instructions.Encode()
	return append(out, c.Msg.Encode9()...)
}

// DecodeCloveRatchet parses a clove. Reference:
// GarlicClove.readBytesRatchet.
func DecodeCloveRatchet(data []byte) (*Clove, error) {
	di, isz, err := DecodeDeliveryInstructions(data)
	if err != nil {
		return nil, err
	}
	msg, err := i2np.Decode9(data[isz:])
	if err != nil {
		return nil, err
	}
	return &Clove{Instructions: *di, Msg: msg}, nil
}

// buildLocalClove wraps an I2NP message in a local-delivery clove.
func buildLocalClove(msg *i2np.Message) *Clove {
	return &Clove{
		Instructions: DeliveryInstructions{Mode: ModeLocal},
		Msg:          msg,
	}
}

// buildRouterClove wraps an I2NP message for router delivery.
func buildRouterClove(msg *i2np.Message, routerHash []byte) *Clove {
	return &Clove{
		Instructions: DeliveryInstructions{Mode: ModeRouter, RouterHash: routerHash},
		Msg:          msg,
	}
}

// buildTunnelClove wraps an I2NP message for tunnel delivery.
func buildTunnelClove(msg *i2np.Message, routerHash []byte, tunnelID uint32) *Clove {
	return &Clove{
		Instructions: DeliveryInstructions{Mode: ModeTunnel, RouterHash: routerHash, TunnelID: tunnelID},
		Msg:          msg,
	}
}

// buildDestinationClove wraps an I2NP message for delivery to an
// encrypted lease set destination hash.
func buildDestinationClove(msg *i2np.Message, destHash []byte) *Clove {
	return &Clove{
		Instructions: DeliveryInstructions{Mode: ModeDestination, DestinationHash: destHash},
		Msg:          msg,
	}
}

// Package i2np implements the I2NP message layer: the common message
// header (full 16-byte and NTCP2 9-byte variants) and the netdb and
// tunnel message bodies a client router exchanges with its peers.
//
// This package mirrors the Java reference implementation files
// router/java/src/net/i2p/data/i2np/{I2NPMessageImpl,
// DatabaseStoreMessage, DatabaseLookupMessage, DatabaseSearchReplyMessage,
// DeliveryStatusMessage, GarlicMessage, TunnelDataMessage,
// TunnelGatewayMessage, DataMessage}.java in the I2P reference router
// (../i2p.i2p).
package i2np

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// I2NP message types. Reference: I2NPMessageImpl.createMessage.
const (
	TypeDatabaseStore            = 1
	TypeDatabaseLookup           = 2
	TypeDatabaseSearchReply      = 3
	TypeDeliveryStatus           = 10
	TypeGarlic                   = 11
	TypeTunnelData               = 18
	TypeTunnelGateway            = 19
	TypeData                     = 20
	TypeTunnelBuild              = 21
	TypeTunnelBuildReply         = 22
	TypeVariableTunnelBuild      = 23
	TypeVariableTunnelBuildReply = 24
	TypeShortTunnelBuild         = 25
	TypeOutboundTunnelBuildReply = 26
)

// Database entry type codes. Reference: DatabaseEntry.java.
const (
	DbRouterInfo   = 0
	DbLeaseSet     = 1
	DbLeaseSet2    = 3
	DbEncryptedLS2 = 5
	DbMetaLS2      = 7
)

// MaxPayload is the largest I2NP body (2-byte size field).
const MaxPayload = 65535

// DefaultExpiration is the default message lifetime.
const DefaultExpiration = 60 * time.Second

// Message is an I2NP message: the header fields plus the raw body.
// Reference: I2NPMessageImpl.
type Message struct {
	Type       int
	ID         uint32
	Expiration time.Time
	Payload    []byte
}

// New creates a message with a random ID and the default expiration.
func New(msgType int, payload []byte) *Message {
	var id [4]byte
	now := time.Now()
	binary.BigEndian.PutUint32(id[:], uint32(now.UnixNano()))
	return &Message{
		Type:       msgType,
		ID:         binary.BigEndian.Uint32(id[:]),
		Expiration: now.Add(DefaultExpiration),
		Payload:    payload,
	}
}

// Encode16 returns the full-header serialization used inside tunnel
// payloads and ElGamal garlic cloves: type, ID, ms expiration, size,
// checksum, payload. Reference: I2NPMessageImpl.toByteArray.
func (m *Message) Encode16() []byte {
	buf := make([]byte, 16+len(m.Payload))
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:5], m.ID)
	binary.BigEndian.PutUint64(buf[5:13], uint64(m.Expiration.UnixMilli()))
	binary.BigEndian.PutUint16(buf[13:15], uint16(len(m.Payload)))
	sum := sha256.Sum256(m.Payload)
	buf[15] = sum[0]
	copy(buf[16:], m.Payload)
	return buf
}

// Decode16 parses a full-header message. Reference:
// I2NPMessageImpl.readMessage.
func Decode16(b []byte) (*Message, error) {
	if len(b) < 16 {
		return nil, fmt.Errorf("i2np: short header %d", len(b))
	}
	m := &Message{Type: int(b[0])}
	m.ID = binary.BigEndian.Uint32(b[1:5])
	m.Expiration = time.UnixMilli(int64(binary.BigEndian.Uint64(b[5:13])))
	size := int(binary.BigEndian.Uint16(b[13:15]))
	if len(b) != 16+size {
		return nil, fmt.Errorf("i2np: size %d but %d body bytes", size, len(b)-16)
	}
	m.Payload = append([]byte(nil), b[16:]...)
	sum := sha256.Sum256(m.Payload)
	if sum[0] != b[15] {
		return nil, fmt.Errorf("i2np: checksum mismatch")
	}
	return m, nil
}

// Encode9 returns the NTCP2/SSU2 raw serialization used in transport
// data frames and ECIES-ratchet garlic cloves: type, ID, expiration
// seconds, payload (no size, no checksum — the frame supplies both).
// Reference: I2NPMessageImpl.toRawByteArrayNTCP2.
func (m *Message) Encode9() []byte {
	buf := make([]byte, 9+len(m.Payload))
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:5], m.ID)
	binary.BigEndian.PutUint32(buf[5:9], uint32((m.Expiration.UnixMilli()+500)/1000))
	copy(buf[9:], m.Payload)
	return buf
}

// Decode9 parses a 9-byte-header message. Reference:
// I2NPMessageImpl.fromRawByteArrayNTCP2.
func Decode9(b []byte) (*Message, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("i2np: short raw header %d", len(b))
	}
	m := &Message{Type: int(b[0])}
	m.ID = binary.BigEndian.Uint32(b[1:5])
	m.Expiration = time.UnixMilli(int64(binary.BigEndian.Uint32(b[5:9]))*1000 + 500)
	m.Payload = append([]byte(nil), b[9:]...)
	return m, nil
}

// DatabaseStore publishes an RI or LeaseSet to the netdb.
// Reference: DatabaseStoreMessage.
type DatabaseStore struct {
	Key          data.Hash
	Kind         int // DbRouterInfo / DbLeaseSet2 / ...
	ReplyToken   uint32
	ReplyTunnel  uint32
	ReplyGateway data.Hash
	// RouterInfo is the (uncompressed) RI bytes for DbRouterInfo.
	RouterInfo []byte
	// Entry is the inline LeaseSet bytes for LeaseSet kinds.
	Entry []byte
}

// Payload serializes the body. RIs are gzip-compressed on the wire.
func (m *DatabaseStore) Payload() []byte {
	buf := make([]byte, 0, 64+len(m.RouterInfo)+len(m.Entry))
	buf = append(buf, m.Key[:]...)
	buf = append(buf, byte(m.Kind))
	buf = binary.BigEndian.AppendUint32(buf, m.ReplyToken)
	if m.ReplyToken > 0 {
		buf = binary.BigEndian.AppendUint32(buf, m.ReplyTunnel)
		buf = append(buf, m.ReplyGateway[:]...)
	}
	if m.Kind == DbRouterInfo {
		compressed := gzipCompress(m.RouterInfo)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(compressed)))
		buf = append(buf, compressed...)
	} else {
		buf = append(buf, m.Entry...)
	}
	return buf
}

// ParseDatabaseStore decodes a DatabaseStore body.
func ParseDatabaseStore(b []byte) (*DatabaseStore, error) {
	if len(b) < 32+1+4 {
		return nil, fmt.Errorf("i2np: short database store %d", len(b))
	}
	m := &DatabaseStore{}
	copy(m.Key[:], b[:32])
	m.Kind = int(b[32] & 0x0f)
	b = b[33:]
	m.ReplyToken = binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if m.ReplyToken > 0 {
		if len(b) < 4+32 {
			return nil, fmt.Errorf("i2np: short reply info")
		}
		m.ReplyTunnel = binary.BigEndian.Uint32(b[:4])
		copy(m.ReplyGateway[:], b[4:36])
		b = b[36:]
	}
	switch m.Kind {
	case DbRouterInfo:
		if len(b) < 2 {
			return nil, fmt.Errorf("i2np: short compressed size")
		}
		csize := int(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
		if csize <= 0 || len(b) < csize {
			return nil, fmt.Errorf("i2np: compressed RI length %d but %d bytes", csize, len(b))
		}
		ri, err := gzipDecompress(b[:csize])
		if err != nil {
			return nil, fmt.Errorf("i2np: bad compressed RI: %w", err)
		}
		if len(ri) > 64*1024 {
			return nil, fmt.Errorf("i2np: RI too big %d", len(ri))
		}
		m.RouterInfo = ri
	case DbLeaseSet, DbLeaseSet2, DbEncryptedLS2, DbMetaLS2:
		m.Entry = append([]byte(nil), b...)
	default:
		return nil, fmt.Errorf("i2np: unknown db type %d", m.Kind)
	}
	return m, nil
}

// DatabaseLookup queries the floodfill netdb.
// Reference: DatabaseLookupMessage.
type DatabaseLookup struct {
	Key         data.Hash
	From        data.Hash
	Flags       byte
	ReplyTunnel uint32
	Peers       []data.Hash
	// ReplyKey: with FlagRatchet, the X25519 reply public key.
	ReplyKey data.Hash
	// ReplyTags: with FlagEncrypt, ElGamal session tags (unused now).
	ReplyTags []data.Hash
}

// Database lookup flag bits. Reference: DatabaseLookupMessage.
const (
	FlagTunnel  = 0x01
	FlagEncrypt = 0x02
	FlagLS      = 0x04
	FlagRI      = 0x08
	FlagExpl    = 0x0c
	FlagRatchet = 0x10
)

// Payload serializes the body.
func (m *DatabaseLookup) Payload() []byte {
	buf := make([]byte, 0, 32+32+1+4+len(m.Peers)*32+40)
	buf = append(buf, m.Key[:]...)
	buf = append(buf, m.From[:]...)
	buf = append(buf, m.Flags)
	if m.Flags&FlagTunnel != 0 {
		buf = binary.BigEndian.AppendUint32(buf, m.ReplyTunnel)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Peers)))
	for _, p := range m.Peers {
		buf = append(buf, p[:]...)
	}
	if m.Flags&FlagEncrypt != 0 {
		buf = append(buf, m.ReplyKey[:]...)
		buf = append(buf, byte(len(m.ReplyTags)))
		for _, t := range m.ReplyTags {
			buf = append(buf, t[:]...)
		}
	} else if m.Flags&FlagRatchet != 0 {
		buf = append(buf, m.ReplyKey[:]...)
	}
	return buf
}

// ParseDatabaseLookup decodes a DatabaseLookup body.
func ParseDatabaseLookup(b []byte) (*DatabaseLookup, error) {
	if len(b) < 32+32+1+2 {
		return nil, fmt.Errorf("i2np: short database lookup %d", len(b))
	}
	m := &DatabaseLookup{}
	copy(m.Key[:], b[:32])
	copy(m.From[:], b[32:64])
	m.Flags = b[64]
	b = b[65:]
	if m.Flags&FlagTunnel != 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("i2np: short reply tunnel")
		}
		m.ReplyTunnel = binary.BigEndian.Uint32(b[:4])
		b = b[4:]
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("i2np: short peer count")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < n*32 {
		return nil, fmt.Errorf("i2np: truncated peer list %d", n)
	}
	for i := 0; i < n; i++ {
		var p data.Hash
		copy(p[:], b[:32])
		m.Peers = append(m.Peers, p)
		b = b[32:]
	}
	if m.Flags&FlagEncrypt != 0 {
		if len(b) < 32+1 {
			return nil, fmt.Errorf("i2np: short reply key")
		}
		copy(m.ReplyKey[:], b[:32])
		b = b[32:]
		n := int(b[0])
		b = b[1:]
		if len(b) < n*32 {
			return nil, fmt.Errorf("i2np: truncated reply tags")
		}
		for i := 0; i < n; i++ {
			var t data.Hash
			copy(t[:], b[:32])
			m.ReplyTags = append(m.ReplyTags, t)
			b = b[32:]
		}
	} else if m.Flags&FlagRatchet != 0 {
		if len(b) < 32 {
			return nil, fmt.Errorf("i2np: short reply key")
		}
		copy(m.ReplyKey[:], b[:32])
	}
	return m, nil
}

// DatabaseSearchReply reports lookup misses and closer peers.
// Reference: DatabaseSearchReplyMessage.
type DatabaseSearchReply struct {
	Key   data.Hash
	Peers []data.Hash
	From  data.Hash
}

// Payload serializes the body.
func (m *DatabaseSearchReply) Payload() []byte {
	buf := make([]byte, 0, 32+1+len(m.Peers)*32+32)
	buf = append(buf, m.Key[:]...)
	buf = append(buf, byte(len(m.Peers)))
	for _, p := range m.Peers {
		buf = append(buf, p[:]...)
	}
	return append(buf, m.From[:]...)
}

// ParseDatabaseSearchReply decodes a DatabaseSearchReply body.
func ParseDatabaseSearchReply(b []byte) (*DatabaseSearchReply, error) {
	if len(b) < 32+1+32 {
		return nil, fmt.Errorf("i2np: short search reply %d", len(b))
	}
	m := &DatabaseSearchReply{}
	copy(m.Key[:], b[:32])
	n := int(b[32])
	b = b[33:]
	if len(b) < n*32+32 {
		return nil, fmt.Errorf("i2np: truncated search reply")
	}
	for i := 0; i < n; i++ {
		var p data.Hash
		copy(p[:], b[:32])
		m.Peers = append(m.Peers, p)
		b = b[32:]
	}
	copy(m.From[:], b[:32])
	return m, nil
}

// DeliveryStatus is a receipt/test message.
// Reference: DeliveryStatusMessage.
type DeliveryStatus struct {
	ID      uint32
	Arrival time.Time
}

// Payload serializes the body (exactly 12 bytes).
func (m *DeliveryStatus) Payload() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], m.ID)
	binary.BigEndian.PutUint64(buf[4:12], uint64(m.Arrival.UnixMilli()))
	return buf
}

// ParseDeliveryStatus decodes a DeliveryStatus body.
func ParseDeliveryStatus(b []byte) (*DeliveryStatus, error) {
	if len(b) != 12 {
		return nil, fmt.Errorf("i2np: delivery status length %d", len(b))
	}
	m := &DeliveryStatus{ID: binary.BigEndian.Uint32(b[0:4])}
	m.Arrival = time.UnixMilli(int64(binary.BigEndian.Uint64(b[4:12])))
	return m, nil
}

// TunnelData carries one 1024-byte encrypted tunnel payload.
// Reference: TunnelDataMessage.
type TunnelData struct {
	TunnelID uint32
	Data     []byte // exactly 1024 bytes on the wire
}

// TunnelDataSize is the fixed tunnel data payload length.
const TunnelDataSize = 1024

// Payload serializes the body.
func (m *TunnelData) Payload() []byte {
	buf := make([]byte, 4+TunnelDataSize)
	binary.BigEndian.PutUint32(buf[0:4], m.TunnelID)
	copy(buf[4:], m.Data)
	return buf
}

// ParseTunnelData decodes a TunnelData body.
func ParseTunnelData(b []byte) (*TunnelData, error) {
	if len(b) != 4+TunnelDataSize {
		return nil, fmt.Errorf("i2np: tunnel data length %d", len(b))
	}
	m := &TunnelData{TunnelID: binary.BigEndian.Uint32(b[0:4])}
	m.Data = append([]byte(nil), b[4:]...)
	return m, nil
}

// TunnelGateway wraps an I2NP message for entry into a tunnel.
// Reference: TunnelGatewayMessage. The embedded message uses the full
// 16-byte header.
type TunnelGateway struct {
	TunnelID uint32
	Message  []byte // full 16-byte-header I2NP message
}

// Payload serializes the body: tunnelId(4) | len(2) | message.
func (m *TunnelGateway) Payload() []byte {
	buf := make([]byte, 0, 6+len(m.Message))
	buf = binary.BigEndian.AppendUint32(buf, m.TunnelID)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Message)))
	return append(buf, m.Message...)
}

// ParseTunnelGateway decodes a TunnelGateway body.
func ParseTunnelGateway(b []byte) (*TunnelGateway, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("i2np: short tunnel gateway %d", len(b))
	}
	m := &TunnelGateway{TunnelID: binary.BigEndian.Uint32(b[0:4])}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) != 6+n {
		return nil, fmt.Errorf("i2np: tunnel gateway size %d but %d bytes", n, len(b)-6)
	}
	m.Message = append([]byte(nil), b[6:]...)
	return m, nil
}

// DataMessage carries arbitrary data (used for RI replies in tests).
// Reference: DataMessage.
type DataMessage struct {
	Data []byte
}

// Payload serializes the body: 4-byte length + data.
func (m *DataMessage) Payload() []byte {
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(m.Data)))
	return append(buf, m.Data...)
}

// ParseDataMessage decodes a DataMessage body.
func ParseDataMessage(b []byte) (*DataMessage, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("i2np: short data message")
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if len(b) != 4+n {
		return nil, fmt.Errorf("i2np: data message size %d but %d bytes", n, len(b)-4)
	}
	return &DataMessage{Data: append([]byte(nil), b[4:]...)}, nil
}

// GarlicMessage body: 4-byte length + ciphertext.
// Reference: GarlicMessage.
type GarlicMessage struct {
	Data []byte
}

// Payload serializes the body.
func (m *GarlicMessage) Payload() []byte {
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(m.Data)))
	return append(buf, m.Data...)
}

// ParseGarlicMessage decodes a GarlicMessage body.
func ParseGarlicMessage(b []byte) (*GarlicMessage, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("i2np: short garlic message")
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if len(b) != 4+n {
		return nil, fmt.Errorf("i2np: garlic size %d but %d bytes", n, len(b)-4)
	}
	return &GarlicMessage{Data: append([]byte(nil), b[4:]...)}, nil
}

// gzipCompress compresses with a gzip header/footer (RFC 1952), as
// DataHelper.compress does. Level 6 = Java's default compression.
func gzipCompress(b []byte) []byte {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, 6)
	if err != nil {
		panic("i2np: gzip: " + err.Error())
	}
	if _, err := w.Write(b); err != nil {
		panic("i2np: gzip write: " + err.Error())
	}
	if err := w.Close(); err != nil {
		panic("i2np: gzip close: " + err.Error())
	}
	return buf.Bytes()
}

// gzipDecompress reverses gzipCompress.
func gzipDecompress(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(r, 128*1024))
	if err != nil {
		return nil, err
	}
	return out, nil
}

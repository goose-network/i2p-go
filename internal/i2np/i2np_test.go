package i2np

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

func ed25519Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func TestHeaderRoundTrip(t *testing.T) {
	m := &Message{
		Type:       TypeDatabaseLookup,
		ID:         0xdeadbeef,
		Expiration: time.UnixMilli(1234567890123),
		Payload:    []byte("body bytes here"),
	}
	got, err := Decode16(m.Encode16())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != m.Type || got.ID != m.ID || !got.Expiration.Equal(m.Expiration) {
		t.Fatalf("header mismatch: %+v", got)
	}
	if !bytes.Equal(got.Payload, m.Payload) {
		t.Fatalf("payload mismatch")
	}
	// Tamper with the checksum.
	enc := m.Encode16()
	enc[15] ^= 1
	if _, err := Decode16(enc); err == nil {
		t.Fatal("bad checksum accepted")
	}

	// 9-byte raw header: seconds resolution.
	got9, err := Decode9(m.Encode9())
	if err != nil {
		t.Fatal(err)
	}
	if got9.Type != m.Type || got9.ID != m.ID {
		t.Fatalf("raw header mismatch: %+v", got9)
	}
	if d := got9.Expiration.Sub(m.Expiration); d > 1000*time.Millisecond || d < -500*time.Millisecond {
		t.Fatalf("raw expiration off by %v", d)
	}
	if !bytes.Equal(got9.Payload, m.Payload) {
		t.Fatal("raw payload mismatch")
	}
}

func TestDatabaseStoreRoundTrip(t *testing.T) {
	ri, _, _ := testRI(t)
	m := &DatabaseStore{
		Key:         data.Hash(sha(ri.Bytes())),
		Kind:        DbRouterInfo,
		ReplyToken:  7,
		ReplyTunnel: 9,
		ReplyGateway: data.Hash(sha([]byte("gateway"))),
		RouterInfo:  ri.Bytes(),
	}
	got, err := ParseDatabaseStore(m.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != m.Key || got.ReplyToken != m.ReplyToken || got.ReplyTunnel != m.ReplyTunnel || got.ReplyGateway != m.ReplyGateway {
		t.Fatalf("mismatch: %+v", got)
	}
	if !bytes.Equal(got.RouterInfo, m.RouterInfo) {
		t.Fatal("RI mismatch")
	}
	// Round-trip through a parsed RI.
	ri2, err := data.ReadRouterInfo(got.RouterInfo, true)
	if err != nil {
		t.Fatal("RI re-parse:", err)
	}
	if ri2.RouterHash() != ri.RouterHash() {
		t.Fatal("RI hash mismatch")
	}
	// LeaseSet kind passes through opaque bytes.
	ls := &DatabaseStore{Kind: DbLeaseSet2, Entry: []byte{0x00, 0x01, 0x02, 0x03}}
	gotLS, err := ParseDatabaseStore(ls.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotLS.Entry, ls.Entry) {
		t.Fatal("LS bytes mismatch")
	}
}

func TestLookupRoundTrip(t *testing.T) {
	m := &DatabaseLookup{
		Key:         data.Hash(sha([]byte("key"))),
		From:        data.Hash(sha([]byte("from"))),
		Flags:       FlagTunnel | FlagRatchet,
		ReplyTunnel: 42,
		Peers:       []data.Hash{data.Hash(sha([]byte("p1"))), data.Hash(sha([]byte("p2")))},
		ReplyKey:    data.Hash(sha([]byte("rk"))),
	}
	got, err := ParseDatabaseLookup(m.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != m.Key || got.From != m.From || got.Flags != m.Flags || got.ReplyTunnel != m.ReplyTunnel {
		t.Fatalf("mismatch: %+v", got)
	}
	if len(got.Peers) != 2 || got.Peers[1] != m.Peers[1] || got.ReplyKey != m.ReplyKey {
		t.Fatalf("mismatch: %+v", got)
	}

	reply := &DatabaseSearchReply{
		Key:   m.Key,
		Peers: m.Peers,
		From:  m.From,
	}
	gotReply, err := ParseDatabaseSearchReply(reply.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if gotReply.Key != reply.Key || gotReply.From != reply.From || len(gotReply.Peers) != 2 {
		t.Fatalf("mismatch: %+v", gotReply)
	}
}

func TestMiscRoundTrips(t *testing.T) {
	dsm := &DeliveryStatus{ID: 99, Arrival: time.UnixMilli(1700000000000)}
	got, err := ParseDeliveryStatus(dsm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 99 || got.Arrival.UnixMilli() != 1700000000000 {
		t.Fatalf("mismatch: %+v", got)
	}

	td := &TunnelData{TunnelID: 1234, Data: bytes.Repeat([]byte{0xAB}, TunnelDataSize)}
	gotTD, err := ParseTunnelData(td.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if gotTD.TunnelID != 1234 || !bytes.Equal(gotTD.Data, td.Data) {
		t.Fatal("tunnel data mismatch")
	}

	inner := New(TypeData, []byte("wrapped"))
	tg := &TunnelGateway{TunnelID: 77, Message: inner.Encode16()}
	gotTG, err := ParseTunnelGateway(tg.Payload())
	if err != nil {
		t.Fatal(err)
	}
	gotInner, err := Decode16(gotTG.Message)
	if err != nil {
		t.Fatal(err)
	}
	if gotInner.Type != TypeData || !bytes.Equal(gotInner.Payload, []byte("wrapped")) {
		t.Fatalf("inner mismatch: %+v", gotInner)
	}

	dm := &DataMessage{Data: bytes.Repeat([]byte{5}, 100)}
	gotDM, err := ParseDataMessage(dm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDM.Data, dm.Data) {
		t.Fatal("data mismatch")
	}

	gm := &GarlicMessage{Data: bytes.Repeat([]byte{9}, 33)}
	gotGM, err := ParseGarlicMessage(gm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotGM.Data, gm.Data) {
		t.Fatal("garlic mismatch")
	}
}

func testRI(t *testing.T) (data.RouterInfo, []byte, error) {
	t.Helper()
	ri, raw := buildTestRI(t)
	return ri, raw, nil
}

// buildTestRI constructs a minimal signed RouterInfo.
func buildTestRI(t *testing.T) (data.RouterInfo, []byte) {
	t.Helper()
	_, priv, err := ed25519Generate()
	if err != nil {
		t.Fatal(err)
	}
	ri := data.RouterInfo{
		Identity: data.RouterIdentity{
			EncKey:     bytes.Repeat([]byte{0x11}, 32),
			SigningKey: priv[32:],
			SigType:    data.SigEdDSA_SHA512_Ed25519,
			EncType:    data.EncECIES_X25519,
		},
		Published: time.UnixMilli(1700000000000),
		Options: map[string]string{
			"caps": "R",
			"netId": "2",
		},
	}
	if err := ri.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ri, ri.Bytes()
}

func sha(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

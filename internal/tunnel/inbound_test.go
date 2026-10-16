package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// buildLiveTunnel runs a full accepted build and returns the live
// tunnel plus R's side (keys + identity).
func buildLiveTunnel(t *testing.T) (*InboundTunnel, *HopKeys, data.Hash) {
	t.Helper()
	ri, rPriv := testRouterIdentity(t)
	ourHash := data.Hash{}
	rand.Read(ourHash[:])
	now := time.Now()
	stbm, pending, err := BuildInbound(ri, ourHash, now)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := ParseIncomingSTBM(stbm, ri.RouterHash(), rPriv, ourHash)
	if err != nil || ib == nil {
		t.Fatalf("R parse: %v %v", err, ib)
	}
	// R joins the tunnel as IBGW: from here on it holds the same keys
	// the creator derived (verified in TestOneHopInboundBuild).
	reply := ib.BuildReplySTBM(0)
	tun, result, err := pending.Resolve(reply)
	if err != nil {
		t.Fatal(err)
	}
	if tun == nil || !result.Accepted {
		t.Fatalf("resolve failed: %+v", result)
	}
	return tun, ib.Keys, ri.RouterHash()
}

// TestInboundDataPath pushes a TunnelGateway message "through R" (as R
// would) and expects it to pop out at our endpoint, reassembled and
// decrypted.
//
// R's side of the data path (InboundGatewayProcessor.process +
// InboundGatewayReceiver.receiveTunnelMessage):
//
//	TGM(RTunnelID, msg) -> verify/preprocess into 1024B blocks ->
//	LayerEncrypt each with R's keys -> TunnelData(IBEPTunnelID) -> us
func TestInboundDataPath(t *testing.T) {
	tun, rKeys, rHash := buildLiveTunnel(t)

	// The payload R delivers into the tunnel: a Garlic message for us.
	garlicBody := make([]byte, 800)
	rand.Read(garlicBody)
	inner := i2np.New(i2np.TypeGarlic, garlicBody)
	inner.ID = 0xdeadbeef
	inner.Expiration = time.Now().Add(10 * time.Minute)

	// R's IBGW pipeline: fragment the full-header message and encrypt
	// each block with its layer keys.
	encoded := inner.Encode16()
	blocks, err := PreprocessMessage(encoded, inner.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range blocks {
		if err := LayerEncrypt(b, rKeys.LayerKey, rKeys.IVKey); err != nil {
			t.Fatal(err)
		}
		td := &i2np.TunnelData{TunnelID: tun.IBEPTunnelID, Data: b}
		got, err := tun.HandleTunnelData(td, rHash)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		for _, m := range got {
			if m.Type != i2np.TypeGarlic {
				t.Fatalf("delivered type %d", m.Type)
			}
			if m.ID != inner.ID {
				t.Fatalf("delivered ID %x", m.ID)
			}
			if !bytes.Equal(m.Payload, garlicBody) {
				t.Fatal("delivered payload mismatch")
			}
			return // complete
		}
	}
	t.Fatal("message never delivered")
}

// TestInboundDataPathFragmented exercises the same path with a payload
// big enough to span several tunnel messages.
func TestInboundDataPathFragmented(t *testing.T) {
	tun, rKeys, rHash := buildLiveTunnel(t)

	body := make([]byte, 5000)
	rand.Read(body)
	inner := i2np.New(i2np.TypeData, body)

	encoded := inner.Encode16()
	blocks, err := PreprocessMessage(encoded, inner.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) < 5 {
		t.Fatalf("expected several blocks, got %d", len(blocks))
	}
	var delivered []*i2np.Message
	for i, b := range blocks {
		if err := LayerEncrypt(b, rKeys.LayerKey, rKeys.IVKey); err != nil {
			t.Fatal(err)
		}
		td := &i2np.TunnelData{TunnelID: tun.IBEPTunnelID, Data: b}
		got, err := tun.HandleTunnelData(td, rHash)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		delivered = append(delivered, got...)
	}
	if len(delivered) != 1 {
		t.Fatalf("delivered %d messages", len(delivered))
	}
	if !bytes.Equal(delivered[0].Payload, body) {
		t.Fatal("delivered payload mismatch")
	}
}

// TestInboundDataReplay checks that a duplicate IV is rejected.
func TestInboundDataReplay(t *testing.T) {
	tun, rKeys, rHash := buildLiveTunnel(t)

	inner := i2np.New(i2np.TypeData, make([]byte, 64))
	encoded := inner.Encode16()
	blocks, err := PreprocessMessage(encoded, inner.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := blocks[0]
	if err := LayerEncrypt(b, rKeys.LayerKey, rKeys.IVKey); err != nil {
		t.Fatal(err)
	}
	td := &i2np.TunnelData{TunnelID: tun.IBEPTunnelID, Data: b}
	if _, err := tun.HandleTunnelData(td, rHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tun.HandleTunnelData(td, rHash); err == nil {
		t.Fatal("replay accepted")
	}
}

// TestInboundDataWrongSender checks that data from anyone but R is
// rejected at the endpoint.
func TestInboundDataWrongSender(t *testing.T) {
	tun, _, _ := buildLiveTunnel(t)
	bad := data.Hash{}
	rand.Read(bad[:])
	td := &i2np.TunnelData{TunnelID: tun.IBEPTunnelID, Data: make([]byte, PreprocessedSize)}
	if _, err := tun.HandleTunnelData(td, bad); err == nil {
		t.Fatal("data from wrong router accepted")
	}
}

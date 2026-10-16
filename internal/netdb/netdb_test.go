package netdb

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/i2np"
)

// fakeSender records sent messages and lets the test inject replies.
type fakeSender struct {
	sent    map[data.Hash][][]byte
	handler func(raw []byte)
}

func newFakeSender() *fakeSender {
	return &fakeSender{sent: make(map[data.Hash][][]byte)}
}

func (f *fakeSender) SendI2NP(to data.Hash, raw []byte) error {
	f.sent[to] = append(f.sent[to], raw)
	// Deliver the reply asynchronously, like a floodfill would.
	if f.handler != nil {
		go f.handler(raw)
	}
	return nil
}

// testFloodfill builds a minimal floodfill RI with a per-seed identity.
func testFloodfill(t *testing.T, seed byte) *data.RouterInfo {
	t.Helper()
	priv := make([]byte, 32)
	pub := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i+1) ^ seed
		pub[i] = byte(i+2) ^ seed
	}
	signing := make([]byte, 32)
	for i := range signing {
		signing[i] = byte(seed) ^ byte(3*i)
	}
	skey := ed25519.NewKeyFromSeed(signing)
	ri := &data.RouterInfo{
		Identity: data.RouterIdentity{
			EncKey:     pub,
			SigningKey: skey.Public().(ed25519.PublicKey),
			SigType:    data.SigEdDSA_SHA512_Ed25519,
			EncType:    data.EncECIES_X25519,
		},
		Published: time.Now(),
		Options:  map[string]string{"caps": "fR"},
	}
	if err := ri.Sign(skey); err != nil {
		t.Fatal(err)
	}
	return ri
}

// TestFloodfillSelection checks caps-based selection.
func TestFloodfillSelection(t *testing.T) {
	db := New(data.Hash{})
	ff := testFloodfill(t, 1)
	db.StoreRI(ff)
	plain := testFloodfill(t, 2)
	plain.Options = map[string]string{"caps": "R"}
	db.StoreRI(plain)
	fills := db.Floodfills()
	if len(fills) != 1 {
		t.Fatalf("got %d floodfills", len(fills))
	}
	if fills[0].RouterHash() != ff.RouterHash() {
		t.Fatal("wrong floodfill selected")
	}
}

// TestLookupRI runs a lookup round against a simulated floodfill that
// answers with a DatabaseStore containing a fresh RI.
func TestLookupRI(t *testing.T) {
	db := New(data.Hash{})
	ff := testFloodfill(t, 1)
	db.StoreRI(ff)
	target := testFloodfill(t, 3) // the RI we're looking up
	targetBytes := target.Bytes()

	sender := newFakeSender()
	client := NewLookupClient(db, sender)
	sender.handler = func(raw []byte) {
		msg, err := i2np.Decode9(raw)
		if err != nil || msg.Type != i2np.TypeDatabaseLookup {
			return
		}
		lk, err := i2np.ParseDatabaseLookup(msg.Payload)
		if err != nil {
			return
		}
		if lk.Key != target.RouterHash() {
			return
		}
		if lk.From != db.OurHash {
			t.Errorf("lookup from %s, expected us", lk.From)
		}
		if lk.Flags != i2np.FlagRI {
			t.Errorf("lookup flags %d", lk.Flags)
		}
		// Floodfill answers: DatabaseStore with the RI (gzipped on the
		// wire by Payload()).
		store := &i2np.DatabaseStore{
			Key:        lk.Key,
			Kind:       i2np.DbRouterInfo,
			RouterInfo: targetBytes,
		}
		reply := i2np.New(i2np.TypeDatabaseStore, store.Payload())
		reply.ID = msg.ID
		client.HandleReply(reply.Encode9())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := client.LookupRI(ctx, target.RouterHash())
	if err != nil {
		t.Fatal(err)
	}
	if got.RouterHash() != target.RouterHash() {
		t.Fatal("wrong RI returned")
	}
	// Now cached locally.
	if db.GetRI(target.RouterHash()) == nil {
		t.Fatal("RI not stored locally")
	}
	if len(sender.sent[ff.RouterHash()]) == 0 {
		t.Fatal("lookup never sent to the floodfill")
	}
}

// TestLookupDSRChase checks that a DatabaseSearchReply does not resolve
// the lookup (we keep waiting).
func TestLookupDSRChase(t *testing.T) {
	db := New(data.Hash{})
	ff := testFloodfill(t, 1)
	db.StoreRI(ff)
	key := data.Hash{}
	for i := range key {
		key[i] = byte(i)
	}

	sender := newFakeSender()
	client := NewLookupClient(db, sender)
	sender.handler = func(raw []byte) {
		msg, err := i2np.Decode9(raw)
		if err != nil || msg.Type != i2np.TypeDatabaseLookup {
			return
		}
		lk, err := i2np.ParseDatabaseLookup(msg.Payload)
		if err != nil || lk.Key != key {
			return
		}
		dsr := &i2np.DatabaseSearchReply{Key: key, Peers: []data.Hash{ff.RouterHash()}, From: ff.RouterHash()}
		reply := i2np.New(i2np.TypeDatabaseSearchReply, dsr.Payload())
		client.HandleReply(reply.Encode9())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := client.LookupRI(ctx, key); err == nil {
		t.Fatal("lookup resolved by a DSR")
	}
}

// TestStoreLS2 runs a store round against a simulated floodfill that
// acks with a DeliveryStatus carrying our token.
func TestStoreLS2(t *testing.T) {
	db := New(data.Hash{})
	ff := testFloodfill(t, 1)
	db.StoreRI(ff)

	// Build a destination + LeaseSet2 by hand (there is no
	// NewDestination helper yet).
	dest := &data.Destination{
		EncKey:     make([]byte, 32),
		SigningKey: make([]byte, 32),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	for i := range dest.EncKey {
		dest.EncKey[i] = byte(i)
	}
	signing := make([]byte, 32)
	for i := range signing {
		signing[i] = byte(32 - i)
	}
	priv := ed25519.NewKeyFromSeed(signing)
	dest.SigningKey = priv.Public().(ed25519.PublicKey)
	lease := data.Lease{
		Gateway:  ff.RouterHash(),
		TunnelID: 12345,
		End:      time.Now().Add(10 * time.Minute),
	}
	ls := &data.LeaseSet2{
		Destination:     *dest,
		Published:       time.Now(),
		Expires:         time.Now().Add(10 * time.Minute),
		EncryptionKeys:  []data.PublicKey{{EncType: data.EncECIES_X25519, Key: dest.EncKey}},
		Leases:          []data.Lease{lease},
	}
	if err := ls.Sign(priv); err != nil {
		t.Fatal(err)
	}

	sender := newFakeSender()
	store := NewStoreClient(db, sender)
	sender.handler = func(raw []byte) {
		msg, err := i2np.Decode9(raw)
		if err != nil || msg.Type != i2np.TypeDatabaseStore {
			return
		}
		ds, err := i2np.ParseDatabaseStore(msg.Payload)
		if err != nil {
			return
		}
		if ds.Key != data.DestinationHash(*dest) {
			return
		}
		// Floodfill acks: DeliveryStatus with the reply token as its ID.
		st := &i2np.DeliveryStatus{ID: ds.ReplyToken, Arrival: time.Now()}
		reply := i2np.New(i2np.TypeDeliveryStatus, st.Payload())
		reply.ID = ds.ReplyToken
		store.HandleDeliveryStatus(reply.Encode9())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.StoreLS2(ctx, ls); err != nil {
		t.Fatal(err)
	}
	// The store message must carry the LS2 and a reply token.
	var found bool
	for _, raw := range sender.sent[ff.RouterHash()] {
		msg, err := i2np.Decode9(raw)
		if err != nil || msg.Type != i2np.TypeDatabaseStore {
			continue
		}
		ds, err := i2np.ParseDatabaseStore(msg.Payload)
		if err != nil {
			continue
		}
		if ds.Kind == i2np.DbLeaseSet2 && len(ds.Entry) > 0 && ds.ReplyToken > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("store message malformed")
	}
}

package socks5

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/streaming"
)

// testDest builds a destination with a given key seed.
func testDest(t *testing.T, seed byte) (*data.Destination, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	enc := make([]byte, 32)
	for i := range enc {
		enc[i] = seed*7 + byte(i)
	}
	dest := &data.Destination{
		EncKey:     enc,
		SigningKey: priv.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}
	return dest, priv
}

// fakeResolver maps hostnames to destinations.
type fakeResolver struct {
	mu    sync.Mutex
	hosts map[string]*data.Destination
	calls []string
}

func (f *fakeResolver) LookupDestination(ctx context.Context, host string) (*data.Destination, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, host)
	return f.hosts[host], nil
}

// echoServer accepts streaming connections and echoes bytes back.
func echoServer(m *streaming.Manager) {
	for {
		s, err := m.Accept(context.Background())
		if err != nil {
			return
		}
		go func(s *streaming.Stream) {
			io.Copy(s, s)
			s.Close()
		}(s)
	}
}

// loopTransport routes packets between two in-memory streaming
// managers, simulating the I2P network: the raw packet is wrapped in
// the I2CP payload format (proto + ports in the gzip header) and
// delivered to the peer's HandleMessage. It mirrors the transport in
// streaming's own tests, but keys peers by destination since Manager's
// internal hash is not exported.
type loopTransport struct {
	mu    sync.Mutex
	peers map[data.Hash]*streaming.Manager
}

func (tr *loopTransport) add(dest *data.Destination, m *streaming.Manager) {
	tr.mu.Lock()
	tr.peers[data.DestinationHash(*dest)] = m
	tr.mu.Unlock()
}

func (tr *loopTransport) SendPacket(to *data.Destination, packet []byte, fromPort, toPort uint16) error {
	gz, err := streaming.CompressPayload(packet, streaming.ProtoStreaming, fromPort, toPort)
	if err != nil {
		return err
	}
	tr.mu.Lock()
	peer := tr.peers[data.DestinationHash(*to)]
	tr.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("socks5 test transport: no manager for destination")
	}
	go peer.HandleMessage(gz)
	return nil
}

// setup starts a SOCKS5 server on a loopback port with an echo
// service behind it, returning the proxy address and the service
// destination.
func setup(t *testing.T) (addr string, dest *data.Destination) {
	t.Helper()

	// Two streaming managers over an in-memory transport.
	tr := &loopTransport{peers: make(map[data.Hash]*streaming.Manager)}
	destA, privA := testDest(t, 1)
	destB, privB := testDest(t, 2)
	mA := streaming.NewManager(destA, privA, tr, streaming.Options{})
	mB := streaming.NewManager(destB, privB, tr, streaming.Options{})
	tr.add(destA, mA)
	tr.add(destB, mB)
	go echoServer(mB)

	resolver := &fakeResolver{hosts: map[string]*data.Destination{
		"echo.i2p":            destB,
		destB.Base32Address(): destB,
	}}
	srv := &Server{Resolver: resolver, Dialer: mA}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { l.Close() })
	return l.Addr().String(), destB
}

// socksConnect performs a SOCKS5 CONNECT to host:port through conn.
func socksConnect(t *testing.T, conn net.Conn, host string, port uint16) byte {
	t.Helper()
	// greeting
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(conn, m[:]); err != nil {
		t.Fatal(err)
	}
	if m[0] != 5 || m[1] != 0 {
		t.Fatalf("greeting reply %v", m)
	}
	// CONNECT request
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 5 {
		t.Fatalf("reply version %d", rep[0])
	}
	return rep[1]
}

// TestConnectEcho dials a name through the proxy and echoes data.
func TestConnectEcho(t *testing.T) {
	addr, _ := setup(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, "echo.i2p", 80); code != 0 {
		t.Fatalf("connect reply %d", code)
	}

	// Write, half-close, read the echo back.
	go func() {
		conn.Write([]byte("hello i2p"))
		// TCP half-close signals EOF to the remote echo side.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello i2p" {
		t.Fatalf("echo %q", got)
	}
}

// TestConnectB32 dials a .b32.i2p address.
func TestConnectB32(t *testing.T) {
	addr, dest := setup(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, dest.Base32Address(), 80); code != 0 {
		t.Fatalf("connect reply %d", code)
	}
	conn.Write([]byte("b32"))
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("not TCP")
	}
	tc.CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "b32" {
		t.Fatalf("echo %q", got)
	}
}

// TestParseInlineDestination checks the base64 destination fallback
// (reference: NamingService.lookupBase64). A full inline destination
// cannot arrive on the SOCKS5 wire — the domain-name length byte caps
// at 255 — but the resolver layer accepts one, as Java's naming
// fallback does for hosts-file values.
func TestParseInlineDestination(t *testing.T) {
	_, dest := setup(t)
	b64 := data.EncodeToI2PBase64(dest.WriteTo(nil))
	if len(b64) < minBase64DestLen {
		t.Fatalf("encoded dest only %d chars", len(b64))
	}
	got, err := parseInlineDestination(b64)
	if err != nil {
		t.Fatal(err)
	}
	if data.DestinationHash(*got) != data.DestinationHash(*dest) {
		t.Fatalf("round-trip mismatch")
	}
	if _, err := parseInlineDestination(string(bytes.Repeat([]byte{'A'}, 600))); err == nil {
		t.Fatal("expected error for garbage base64")
	}
}

// TestRefusals checks the rejection paths.
func TestRefusals(t *testing.T) {
	addr, _ := setup(t)

	cases := []struct {
		name string
		host string
		cmd  byte
		want byte
	}{
		{"localhost", "localhost", 1, replyConnectionNotAllowed},
		{"loopback", "127.0.0.1", 1, replyConnectionNotAllowed},
		{"private", "192.168.1.1", 1, replyConnectionNotAllowed},
		{"clearnet", "example.com", 1, replyConnectionNotAllowed},
		{"unknown-i2p", "nosuch.i2p", 1, replyHostUnreachable},
		{"unknown-b32", strings.Repeat("a", 52) + ".b32.i2p", 1, replyHostUnreachable},
		{"blinded-b32", strings.Repeat("a", 56) + ".b32.i2p", 1, replyHostUnreachable},
		{"bind", "echo.i2p", 2, replyCommandNotSupported},
		{"udp", "echo.i2p", 3, replyCommandNotSupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			var m [2]byte
			if _, err := io.ReadFull(conn, m[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte{5, tc.cmd, 0, 3, byte(len(tc.host))}); err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(tc.host))
			if _, err := conn.Write([]byte{0, 80}); err != nil {
				t.Fatal(err)
			}
			var rep [10]byte
			if _, err := io.ReadFull(conn, rep[:]); err != nil {
				t.Fatal(err)
			}
			if rep[1] != tc.want {
				t.Fatalf("reply %d, want %d", rep[1], tc.want)
			}
		})
	}
}

// TestBadAuth checks NO ACCEPTABLE METHODS when we offer only auth.
func TestBadAuth(t *testing.T) {
	addr, _ := setup(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte{5, 1, 2}) // offer only USERNAME/PASSWORD
	var rep [2]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 5 || rep[1] != 0xff {
		t.Fatalf("reply %v, want [5 255]", rep)
	}
}

// TestIPv4AddressType checks an IPv4 ATYP request resolves through
// the resolver path (the proxy sends no clearnet IPs onward).
func TestIPv4AddressType(t *testing.T) {
	addr, _ := setup(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var m [2]byte
	io.ReadFull(conn, m[:])
	// CONNECT to 10.0.0.1 (ATYP 1)
	if _, err := conn.Write([]byte{5, 1, 0, 1, 10, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != replyConnectionNotAllowed {
		t.Fatalf("reply %d, want %d", rep[1], replyConnectionNotAllowed)
	}
}

package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/streaming"
)

// outproxySetup starts a SOCKS5 server whose non-I2P CONNECTs are
// relayed through a fake outproxy: a streaming peer whose accepted
// connections run serve. Mismatches inside serve surface as protocol
// failures, which the SOCKS client observes as host-unreachable.
func outproxySetup(t *testing.T, cfg *OutproxyConfig, serve func(s *streaming.Stream)) string {
	t.Helper()

	tr := &loopTransport{peers: make(map[data.Hash]*streaming.Manager)}
	destA, privA := testDest(t, 1)
	destB, privB := testDest(t, 2)
	mA := streaming.NewManager(destA, privA, tr, streaming.Options{})
	mB := streaming.NewManager(destB, privB, tr, streaming.Options{})
	tr.add(destA, mA)
	tr.add(destB, mB)
	go func() {
		for {
			s, err := mB.Accept(context.Background())
			if err != nil {
				return
			}
			go serve(s)
		}
	}()

	resolver := &fakeResolver{hosts: map[string]*data.Destination{
		"outproxy.i2p":        destB,
		destB.Base32Address(): destB,
	}}
	srv := &Server{Resolver: resolver, Dialer: mA, Outproxy: cfg}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

// serveSOCKSOutproxy implements the outproxy side of SOCKS5: greeting,
// CONNECT for wantHost:wantPort, reply, then echo. A mismatch gets a
// failure reply, which the client maps to host-unreachable.
func serveSOCKSOutproxy(wantHost string, wantPort uint16) func(*streaming.Stream) {
	return func(s *streaming.Stream) {
		defer s.Close()
		var m [2]byte
		if _, err := io.ReadFull(s, m[:]); err != nil {
			return
		}
		// VER=5 NMETHODS=1, then the single offered method byte.
		var meth [1]byte
		if _, err := io.ReadFull(s, meth[:]); err != nil {
			return
		}
		if m[0] != 5 || m[1] != 1 || meth[0] != 0 {
			return
		}
		s.Write([]byte{5, 0})

		var h [4]byte
		if _, err := io.ReadFull(s, h[:]); err != nil {
			return
		}
		if h[0] != 5 || h[1] != 1 { // VER CONNECT
			return
		}
		var host []byte
		switch h[3] {
		case 3:
			var l [1]byte
			if _, err := io.ReadFull(s, l[:]); err != nil {
				return
			}
			host = make([]byte, l[0])
			io.ReadFull(s, host)
		case 1:
			host = make([]byte, 4)
			io.ReadFull(s, host)
		case 4:
			host = make([]byte, 16)
			io.ReadFull(s, host)
		default:
			return
		}
		var pb [2]byte
		if _, err := io.ReadFull(s, pb[:]); err != nil {
			return
		}
		if string(host) != wantHost || binary.BigEndian.Uint16(pb[:]) != wantPort {
			s.Write([]byte{5, replyHostUnreachable, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		s.Write([]byte{5, replySucceeded, 0, 1, 0, 0, 0, 0, 0, 0})
		io.Copy(s, s)
	}
}

// serveConnectOutproxy implements the outproxy side of HTTP CONNECT:
// it requires the request line "CONNECT wantHost:wantPort HTTP/1.1",
// replies 200 (or rejectStatus when non-empty), then echoes.
func serveConnectOutproxy(wantHost string, wantPort uint16, rejectStatus string) func(*streaming.Stream) {
	return func(s *streaming.Stream) {
		defer s.Close()
		var first string
		for {
			l, err := readTestLine(s)
			if err != nil {
				return
			}
			if first == "" {
				first = l
			}
			if l == "" {
				break // end of headers
			}
		}
		want := fmt.Sprintf("CONNECT %s:%d HTTP/1.1", wantHost, wantPort)
		if first != want {
			s.Write([]byte("HTTP/1.1 400 bad request: " + first + "\r\n\r\n"))
			return
		}
		if rejectStatus != "" {
			s.Write([]byte("HTTP/1.1 " + rejectStatus + "\r\nX-Test: 1\r\n\r\n"))
			return
		}
		s.Write([]byte("HTTP/1.1 200 Connection established\r\nVia: outproxy-test\r\n\r\n"))
		io.Copy(s, s)
	}
}

// readTestLine is the test-side twin of readProxyLine: reads one
// CRLF-terminated line without readahead.
func readTestLine(s *streaming.Stream) (string, error) {
	var b []byte
	for {
		var c [1]byte
		if _, err := io.ReadFull(s, c[:]); err != nil {
			return "", err
		}
		if c[0] == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		b = append(b, c[0])
		if len(b) > 8192 {
			return "", fmt.Errorf("line too long")
		}
	}
}

// TestOutproxySOCKS relays a clearnet CONNECT through a SOCKS-speaking
// outproxy and verifies the end-to-end data path — the fake outproxy
// sees exactly CONNECT www.example.com:443, and bytes echo back.
func TestOutproxySOCKS(t *testing.T) {
	addr := outproxySetup(t, &OutproxyConfig{Addr: "outproxy.i2p", Type: "socks"},
		serveSOCKSOutproxy("www.example.com", 443))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, "www.example.com", 443); code != replySucceeded {
		t.Fatalf("connect reply %d", code)
	}
	go func() {
		conn.Write([]byte("hello outproxy"))
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello outproxy" {
		t.Fatalf("echo %q", got)
	}
}

// TestOutproxyConnect relays a clearnet CONNECT through an HTTP
// CONNECT outproxy. The 200 and its headers must be consumed exactly:
// the payload that follows starts clean.
func TestOutproxyConnect(t *testing.T) {
	addr := outproxySetup(t, &OutproxyConfig{Addr: "outproxy.i2p", Type: "connect"},
		serveConnectOutproxy("www.example.com", 443, ""))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, "www.example.com", 443); code != replySucceeded {
		t.Fatalf("connect reply %d", code)
	}
	go func() {
		conn.Write([]byte("tunneled"))
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tunneled" {
		t.Fatalf("echo %q (handshake bytes leaked into the tunnel?)", got)
	}
}

// TestOutproxyConnectRejection maps a non-200 outproxy reply to a
// SOCKS failure for the local client.
func TestOutproxyConnectRejection(t *testing.T) {
	addr := outproxySetup(t, &OutproxyConfig{Addr: "outproxy.i2p", Type: "connect"},
		serveConnectOutproxy("www.example.com", 443, "403 Forbidden"))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, "www.example.com", 443); code != replyHostUnreachable {
		t.Fatalf("connect reply %d, want host unreachable", code)
	}
}

// TestOutproxyNotResolvable: an outproxy with no addressbook entry
// fails the CONNECT cleanly.
func TestOutproxyNotResolvable(t *testing.T) {
	addr := outproxySetup(t, &OutproxyConfig{Addr: "missing.i2p", Type: "connect"},
		serveConnectOutproxy("www.example.com", 443, ""))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if code := socksConnect(t, conn, "www.example.com", 443); code != replyHostUnreachable {
		t.Fatalf("connect reply %d, want host unreachable", code)
	}
}

// TestOutproxyGating: with an outproxy configured, localhost and LAN
// targets stay refused — they must never be relayed.
func TestOutproxyGating(t *testing.T) {
	addr := outproxySetup(t, &OutproxyConfig{Addr: "outproxy.i2p", Type: "connect"},
		serveConnectOutproxy("www.example.com", 443, ""))
	for _, host := range []string{"localhost", "127.0.0.1", "192.168.1.1", "[::1]"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if code := socksConnect(t, conn, host, 80); code != replyConnectionNotAllowed {
			t.Fatalf("host %q: reply %d, want connection not allowed", host, code)
		}
		conn.Close()
	}
}

// TestOutproxyInlineDestination uses a base64 destination as the
// outproxy address (no addressbook entry needed).
func TestOutproxyInlineDestination(t *testing.T) {
	tr := &loopTransport{peers: make(map[data.Hash]*streaming.Manager)}
	destA, privA := testDest(t, 1)
	destB, privB := testDest(t, 2)
	mA := streaming.NewManager(destA, privA, tr, streaming.Options{})
	mB := streaming.NewManager(destB, privB, tr, streaming.Options{})
	tr.add(destA, mA)
	tr.add(destB, mB)
	go func() {
		for {
			s, err := mB.Accept(context.Background())
			if err != nil {
				return
			}
			go serveConnectOutproxy("www.example.com", 443, "")(s)
		}
	}()

	srv := &Server{
		Resolver: &fakeResolver{hosts: map[string]*data.Destination{}},
		Dialer:   mA,
		Outproxy: &OutproxyConfig{
			Addr: data.EncodeToI2PBase64(destB.WriteTo(nil)),
			Type: "connect",
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { l.Close() })

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if code := socksConnect(t, conn, "www.example.com", 443); code != replySucceeded {
		t.Fatalf("connect reply %d", code)
	}
}

// TestSplitOutproxyAddr covers the "name:port" parsing.
func TestSplitOutproxyAddr(t *testing.T) {
	cases := []struct {
		in   string
		name string
		port uint16
	}{
		{"false.i2p", "false.i2p", 0},
		{"false.i2p:8888", "false.i2p", 8888},
		{"false.i2p:0", "false.i2p", 0},
		{"false.i2p:abc", "false.i2p", 0},
		{":123", ":123", 0}, // leading colon: Java's colon>0 check leaves it whole
	}
	for _, c := range cases {
		name, port := splitOutproxyAddr(c.in)
		if name != c.name || port != c.port {
			t.Fatalf("splitOutproxyAddr(%q) = %q, %d; want %q, %d", c.in, name, port, c.name, c.port)
		}
	}
}

// TestIsI2PHostForm covers the outproxy gate classification.
func TestIsI2PHostForm(t *testing.T) {
	if !isI2PHostForm("zzz.i2p") || !isI2PHostForm("ZZZ.I2P") || !isI2PHostForm("sub.site.i2p.alt") {
		t.Fatal(".i2p name not recognized")
	}
	if !isI2PHostForm(strings.Repeat("a", 52) + ".b32.i2p") {
		t.Fatal("plain b32 not recognized")
	}
	if isI2PHostForm("www.example.com") {
		t.Fatal("clearnet host misclassified as I2P")
	}
	if isI2PHostForm("1.2.3.4") {
		t.Fatal("IP misclassified as I2P")
	}
	if !isI2PHostForm(strings.Repeat("a", 516)) {
		t.Fatal("inline destination not recognized")
	}
}

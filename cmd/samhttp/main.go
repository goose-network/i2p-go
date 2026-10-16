// Command samhttp is a SAM v3 client that hosts a tiny HTTP responder
// on a local i2pd (or Java I2P) SAM bridge. It exists to give our pure
// Go router a known-good counterpart for interop testing: fetch
// http://<b32>.i2p/ through our SOCKS5 and this answers with real HTTP.
//
// Usage: samhttp -sam 127.0.0.1:7656 [-connect <b64-or-b32 dest>]
//
// With -connect it dials out instead (testing the inbound side of our
// router: give it our router's b32).
//
// SAM v3 rules: SESSION CREATE turns its socket into the session
// control socket, so STREAM ACCEPT/CONNECT must be sent over a fresh
// connection.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

func main() {
	samAddr := flag.String("sam", "127.0.0.1:7656", "SAM bridge address")
	connect := flag.String("connect", "", "destination to dial (b64 dest or b32 host) instead of listening")
	flag.Parse()

	// Connection 1: session.
	c1 := samDial(*samAddr)
	samSend(c1, "HELLO VERSION MIN=3.0 MAX=3.2")
	if !samExpectOK(c1, 15*time.Second, "hello") {
		os.Exit(1)
	}
	sid := fmt.Sprintf("i2pgo%d", time.Now().UnixNano()%1e6)
	samSend(c1, "SESSION CREATE STYLE=STREAM ID="+sid+" DESTINATION=TRANSIENT SIGNATURE_TYPE=EdDSA_SHA512_Ed25519")
	line := samExpectLine(c1, 150*time.Second, "session")
	if line == "" {
		os.Exit(1)
	}
	privB64 := ""
	if i := strings.Index(line, "DESTINATION="); i >= 0 {
		privB64 = strings.TrimSpace(line[i+len("DESTINATION="):])
	}
	// The session reply carries the private keys (destination first);
	// the destination's b32 is the address to fetch.
	dest := ""
	if raw, err := data.DecodeI2PBase64(privB64); err == nil {
		if d, _, err := data.ReadDestination(raw); err == nil {
			dest = d.Base32Address()
		}
	}
	fmt.Printf("session OK (id %s)\nSAMHTTP_B32=%s\n", sid, dest)
	if dest == "" {
		fmt.Println("cannot parse destination from session reply")
		os.Exit(1)
	}

	// Connection 2: stream.
	c2 := samDial(*samAddr)
	defer c2.Close()
	samSend(c2, "HELLO VERSION MIN=3.0 MAX=3.2")
	if !samExpectOK(c2, 15*time.Second, "hello2") {
		os.Exit(1)
	}

	if *connect != "" {
		target := *connect
		if len(target) == 52 { // bare b32 prefix
			target += ".b32.i2p"
		}
		samSend(c2, "STREAM CONNECT ID="+sid+" DESTINATION="+target)
		if !samExpectOK(c2, 90*time.Second, "stream connect") {
			os.Exit(1)
		}
		fmt.Println("stream connected; sending HTTP request")
		c2.SetWriteDeadline(time.Now().Add(10 * time.Second))
		c2.Write([]byte("GET / HTTP/1.1\r\nHost: i2pgo\r\n\r\n"))
		c2.SetReadDeadline(time.Now().Add(120 * time.Second))
		buf := make([]byte, 8192)
		for {
			n, err := c2.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
			if err != nil {
				fmt.Println("\nread done:", err)
				return
			}
		}
	}

	samSend(c2, "STREAM ACCEPT ID="+sid+" SILENT=false")
	if !samExpectOK(c2, 30*time.Second, "stream accept") {
		os.Exit(1)
	}
	fmt.Println("stream ACCEPT OK — waiting for incoming connections")

	// Each incoming connection: one line "DESTINATION=<b64>" then the
	// raw stream (SILENT=false).
	r2 := bufio.NewReader(c2)
	for {
		c2.SetReadDeadline(time.Now().Add(30 * time.Minute))
		peer, err := r2.ReadString('\n')
		if err != nil {
			fmt.Println("accept wait done:", err)
			return
		}
		fmt.Printf("incoming: %s...\n", strings.TrimSpace(peer)[:min(40, len(peer))])
		serveHTTP(c2)
	}
}

func samDial(addr string) net.Conn {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Println("sam dial:", err)
		os.Exit(1)
	}
	return conn
}

func samSend(c net.Conn, line string) {
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintln(c, line)
}

func samExpectLine(c net.Conn, timeout time.Duration, stage string) string {
	c.SetReadDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		fmt.Printf("%s: %v\n", stage, err)
		return ""
	}
	if !strings.Contains(line, "RESULT=OK") {
		fmt.Printf("%s: %s\n", stage, strings.TrimSpace(line))
		return ""
	}
	return line
}

func samExpectOK(c net.Conn, timeout time.Duration, stage string) bool {
	return samExpectLine(c, timeout, stage) != ""
}

func serveHTTP(c net.Conn) {
	buf := make([]byte, 4096)
	var req []byte
	deadline := time.Now().Add(8 * time.Second)
	for len(req) < 4096 {
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if n > 0 {
			req = append(req, buf[:n]...)
			if strings.Contains(string(req), "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	first := ""
	if i := strings.IndexByte(string(req), '\n'); i > 0 {
		first = strings.TrimSpace(string(req)[:i])
	}
	fmt.Printf("  request: %q\n", first)
	body := "hello from samhttp via local i2pd\n"
	resp := "HTTP/1.1 200 OK\r\nServer: samhttp\r\nContent-Type: text/plain\r\nContent-Length: " +
		fmt.Sprint(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte(resp))
	time.Sleep(300 * time.Millisecond)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

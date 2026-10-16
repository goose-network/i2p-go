// Package proxy implements the SOCKS5 client used for all outbound
// connections in NAT'd environments: both the HTTPS reseed fetch and
// every NTCP2 connection ride the upstream proxy. Hostnames are
// passed to the proxy for remote DNS resolution, since local DNS may
// be blocked or poisoned.
package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// handshakeTimeout bounds greeting and CONNECT exchange.
const handshakeTimeout = 20 * time.Second

// Dialer connects to TCP addresses through a SOCKS5 proxy.
type Dialer struct {
	// Addr is the proxy address, e.g. "127.0.0.1:7890".
	Addr string
}

// Dial connects to addr ("host:port") through the proxy. The
// hostname is sent to the proxy for resolution (SOCKS5 ATYP 3,
// domain-name), so no local DNS is used. auth is unused (no-auth).
func (d *Dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Addr == "" {
		// No proxy: direct dial.
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad address %q: %v", addr, err)
	}
	pn, err := net.LookupPort(network, port)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad port %q", port)
	}
	if pn < 0 || pn > 65535 {
		return nil, fmt.Errorf("proxy: port %d out of range", pn)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: dial %s: %w", d.Addr, err)
	}
	conn.SetDeadline(deadline)

	// Greeting: VER 5, one method: no authentication.
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: greeting: %w", err)
	}
	var hdr [2]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: greeting reply: %w", err)
	}
	if hdr[0] != 5 {
		conn.Close()
		return nil, fmt.Errorf("proxy: bad version %d in greeting reply", hdr[0])
	}
	if hdr[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy: method 0x%02x not accepted", hdr[1])
	}

	// CONNECT: VER 5, CMD 1 (CONNECT), RSV 0, ATYP 3 (domain).
	req := []byte{5, 1, 0, 3, byte(len(host))}
	if len(host) > 255 {
		conn.Close()
		return nil, fmt.Errorf("proxy: hostname too long")
	}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(pn))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: connect request: %w", err)
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
	var rep [4]byte
	if _, err := readFull(conn, rep[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: connect reply: %w", err)
	}
	if rep[0] != 5 {
		conn.Close()
		return nil, fmt.Errorf("proxy: bad version %d in connect reply", rep[0])
	}
	if rep[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy: connect refused: %s", replyText(rep[1]))
	}
	var addrLen int
	switch rep[3] {
	case 1:
		addrLen = 4
	case 3:
		var l [1]byte
		if _, err := readFull(conn, l[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy: bound addr length: %w", err)
		}
		addrLen = int(l[0])
	case 4:
		addrLen = 16
	default:
		conn.Close()
		return nil, fmt.Errorf("proxy: bound address type %d", rep[3])
	}
	skip := make([]byte, addrLen+2) // bound address + port
	if _, err := readFull(conn, skip); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: bound address: %w", err)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// replyText maps a SOCKS5 reply code to a short description.
func replyText(code byte) string {
	switch code {
	case 1:
		return "general SOCKS server failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	default:
		return fmt.Sprintf("reply code %d", code)
	}
}

// readFull reads exactly len(b) bytes.
func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

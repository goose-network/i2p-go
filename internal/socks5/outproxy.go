// Outproxy forwarding for the SOCKS5 server: a CONNECT naming a
// non-I2P host is relayed through a configured outproxy — an I2P
// destination that fetches the clearnet on the client's behalf. There
// is no Tor-style exit-node pool to choose from; outproxies are
// volunteer-run services reached over I2P streaming.
//
// Two protocols are spoken to the outproxy, mirroring the Java router:
// an HTTP CONNECT exchange (SOCKS5Server.httpsConnect, used by the
// connectclient tunnels) or a full SOCKS5 client handshake
// (net.i2p.socks.SOCKS5Client, used when outproxyType is unset).
package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/streaming"
)

// OutproxyConfig selects the outproxy used for non-I2P hosts.
// Reference: the i2ptunnel.socks.proxy.default and outproxyType
// properties (I2PSOCKSTunnel).
type OutproxyConfig struct {
	// Addr is the outproxy location: an addressbook name, a .b32.i2p
	// host, or a base64 destination — optionally "name:port" to pick
	// the I2P port it serves. Reference: SOCKS5Server.outproxyConnect
	// proxy string parsing.
	Addr string
	// Type is the protocol the outproxy speaks: "connect" (default)
	// or "socks". Reference: I2PSOCKSTunnel.PROP_OUTPROXY_TYPE, where
	// "connect" selects httpsConnect and anything else SOCKS5Client.
	Type string
}

// outproxyTimeout bounds the protocol handshake with the outproxy (the
// HTTP CONNECT round trip or the SOCKS5 exchange). The I2P dial
// beneath it is bounded by the streaming layer's own connect timeout.
// Reference: I2PTunnelHTTPServer.readHeaders is called with 15 s; I2P
// round trips are slow enough to warrant more here.
const outproxyTimeout = 45 * time.Second

// maxProxyHeaderLines and maxProxyLineLen bound what is read from the
// outproxy so a misbehaving one cannot exhaust memory.
const (
	maxProxyHeaderLines = 64
	maxProxyLineLen     = 8192
)

// handleOutproxy runs one SOCKS5 client connection through the
// configured outproxy. Reference: SOCKS5Server.getDestinationI2PSocket
// non-I2P branch — dial the outproxy, complete its handshake, then
// confirm to the local client and pump.
func (s *Server) handleOutproxy(c net.Conn, host string, port uint16, logf func(string, ...any)) {
	c.SetDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stream, err := s.dialOutproxy(ctx, host, port, logf)
	if err != nil {
		logf("outproxy %s:%d: %v", host, port, err)
		s.reply(c, replyHostUnreachable)
		return
	}

	s.reply(c, replySucceeded)
	logf("connected %s:%d via outproxy", host, port)
	s.pump(c, stream)
	logf("closed %s:%d via outproxy", host, port)
}

// splitOutproxyAddr splits "name:port" into the proxy location and its
// I2P port (0 = the streaming default, which outproxy servers accept).
// A bad port is ignored, leaving 0. Reference: outproxyConnect.
func splitOutproxyAddr(addr string) (string, uint16) {
	name := addr
	var port uint16
	if i := strings.Index(addr, ":"); i > 0 {
		if p, err := strconv.ParseUint(addr[i+1:], 10, 16); err == nil && p > 0 {
			port = uint16(p)
		}
		name = addr[:i]
	}
	return name, port
}

// dialOutproxy resolves and dials the outproxy, then completes its
// handshake for host:port. Reference: SOCKS5Server.outproxyConnect.
func (s *Server) dialOutproxy(ctx context.Context, host string, port uint16, logf func(string, ...any)) (*streaming.Stream, error) {
	op := s.Outproxy
	name, proxyPort := splitOutproxyAddr(op.Addr)

	dest := s.outproxyDest(ctx, name, logf)
	if dest == nil {
		return nil, fmt.Errorf("outproxy %q not found", name)
	}

	stream, err := s.Dialer.Dial(ctx, dest, proxyPort)
	if err != nil {
		return nil, fmt.Errorf("outproxy dial: %v", err)
	}

	stream.SetDeadline(time.Now().Add(outproxyTimeout))
	switch op.Type {
	case "", "connect":
		err = outproxyHTTPConnect(stream, host, port)
	case "socks", "socks5":
		err = outproxySOCKS5(stream, host, port)
	default:
		err = fmt.Errorf("unknown outproxy type %q", op.Type)
	}
	stream.SetDeadline(time.Time{})
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("outproxy handshake: %v", err)
	}
	return stream, nil
}

// outproxyDest resolves the outproxy's destination, caching it: a
// destination is static key material, only its leases rotate.
// Reference: outproxyConnect resolves via the naming service per
// connection; a cache is equivalent for names with addressbook entries
// and saves a netdb lookup for .b32 addresses.
func (s *Server) outproxyDest(ctx context.Context, name string, logf func(string, ...any)) *data.Destination {
	if len(name) >= minBase64DestLen {
		dest, err := parseInlineDestination(name)
		if err != nil {
			logf("outproxy destination %s: %v", name, err)
			return nil
		}
		return dest
	}

	s.opMu.Lock()
	dest := s.opCache[name]
	s.opMu.Unlock()
	if dest != nil {
		return dest
	}
	if s.Resolver == nil {
		return nil
	}
	dest, err := s.Resolver.LookupDestination(ctx, name)
	if err != nil {
		logf("outproxy lookup %s: %v", name, err)
		return nil
	}
	if dest == nil {
		return nil
	}
	s.opMu.Lock()
	if s.opCache == nil {
		s.opCache = make(map[string]*data.Destination)
	}
	s.opCache[name] = dest
	s.opMu.Unlock()
	return dest
}

// outproxyHTTPConnect sends an HTTP CONNECT to the outproxy and reads
// its response, leaving the stream positioned at the tunneled payload.
// Reference: SOCKS5Server.httpsConnect.
func outproxyHTTPConnect(stream *streaming.Stream, host string, port uint16) error {
	var b strings.Builder
	b.WriteString("CONNECT ")
	if strings.Contains(host, ":") { // IPv6 literal
		b.WriteByte('[')
		b.WriteString(host)
		b.WriteByte(']')
	} else {
		b.WriteString(host)
	}
	fmt.Fprintf(&b, ":%d", port)
	b.WriteString(" HTTP/1.1\r\n\r\n")
	if _, err := stream.Write([]byte(b.String())); err != nil {
		return err
	}

	// Status line first: "HTTP/1.x 200 ...". Reference: httpsConnect
	// splits on space and requires the rest to start with "200 ".
	line, err := readProxyLine(stream)
	if err != nil {
		return err
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) < 2 || (f[1] != "200" && !strings.HasPrefix(f[1], "200 ")) {
		return fmt.Errorf("error from proxy: %s", line)
	}

	// Eat the remaining headers up to the blank line.
	for i := 0; ; i++ {
		if i > maxProxyHeaderLines {
			return errors.New("outproxy response header overflow")
		}
		line, err = readProxyLine(stream)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

// readProxyLine reads one CRLF-terminated line, one byte at a time so
// that no payload bytes beyond the line are consumed from the stream
// (the pump reads the stream directly afterwards). Reference:
// DataHelper.readLine, which has the same no-readahead property.
func readProxyLine(stream *streaming.Stream) (string, error) {
	var b []byte
	for {
		var c [1]byte
		if _, err := io.ReadFull(stream, c[:]); err != nil {
			return "", err
		}
		if c[0] == '\n' {
			return string(bytes.TrimSuffix(b, []byte{'\r'})), nil
		}
		b = append(b, c[0])
		if len(b) > maxProxyLineLen {
			return "", errors.New("outproxy response line too long")
		}
	}
}

// outproxySOCKS5 speaks SOCKS5 to the outproxy, connecting it to
// host:port. Authentication is not supported; an outproxy that
// requires it fails with a clear error. Reference:
// net.i2p.socks.SOCKS5Client.connect.
func outproxySOCKS5(stream *streaming.Stream, host string, port uint16) error {
	// Greeting: VER=5, one offered method: NO AUTHENTICATION.
	if _, err := stream.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var m [2]byte
	if _, err := io.ReadFull(stream, m[:]); err != nil {
		return err
	}
	if m[0] != 5 {
		return fmt.Errorf("socks version %d", m[0])
	}
	if m[1] != 0 {
		return fmt.Errorf("method 0x%02x (authentication not supported)", m[1])
	}

	// CONNECT request. IP literals go as address bytes, everything
	// else as a domain name. Reference: SOCKS5Client.
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, atypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("host too long")
		}
		req = append(req, atypDomainName, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := stream.Write(req); err != nil {
		return err
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT. The bound address is
	// read and discarded.
	var h [4]byte
	if _, err := io.ReadFull(stream, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return fmt.Errorf("reply version %d", h[0])
	}
	var n int
	switch h[3] {
	case atypIPv4:
		n = 4
	case atypIPv6:
		n = 16
	case atypDomainName:
		var l [1]byte
		if _, err := io.ReadFull(stream, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return fmt.Errorf("reply address type %d", h[3])
	}
	if _, err := io.CopyN(io.Discard, stream, int64(n)+2); err != nil {
		return err
	}
	if h[1] != replySucceeded {
		return fmt.Errorf("proxy rejected request: code 0x%02x", h[1])
	}
	return nil
}

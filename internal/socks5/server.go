// Package socks5 implements a SOCKS5 CONNECT-only proxy front end
// for I2P: it accepts local SOCKS5 clients, resolves .i2p hostnames
// (.b32.i2p via netdb LeaseSet lookups, long base64 strings as inline
// destinations), and bridges them to streaming connections.
//
// Reference: apps/i2ptunnel/java/src/net/i2p/i2ptunnel/socks/
// SOCKS5Server.java in the Java router (../i2p.i2p).
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
	"github.com/goose-network/i2p-go/internal/streaming"
)

// minBase64DestLen is the minimum length of a base64 destination
// string. Reference: NamingService.lookup ("a 516+ character Base 64"
// string is a destination).
const minBase64DestLen = 516

// b32PrefixLen is the base32 length of a plain destination hash (32
// bytes -> 52 chars). Blinded/encrypted-lease-set hosts are longer.
const b32PrefixLen = 52

// Resolver maps hostnames to I2P destinations. It is satisfied by the
// router layer (netdb + addressbook).
type Resolver interface {
	// LookupDestination resolves host to an I2P destination.
	LookupDestination(ctx context.Context, host string) (*data.Destination, error)
}

// Dialer opens streaming connections. It is satisfied by
// streaming.Manager.
type Dialer interface {
	Dial(ctx context.Context, remote *data.Destination, port uint16) (*streaming.Stream, error)
}

// Server is a SOCKS5 CONNECT proxy over I2P streaming.
type Server struct {
	Resolver Resolver
	Dialer   Dialer
	Log      *log.Logger
}

// Serve accepts connections until the listener closes, handling each
// on its own goroutine.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

// ListenAndServe listens on addr and serves until a fatal error.
func (s *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// SOCKS5 reply codes. Reference: SOCKS5Constants.Reply.
const (
	replySucceeded             = 0x00
	replyGeneralFailure        = 0x01
	replyConnectionNotAllowed  = 0x03
	replyHostUnreachable       = 0x04
	replyCommandNotSupported   = 0x07
	replyAddressTypeNotSupport = 0x08
)

// Address type constants. Reference: SOCKS5Constants.AddressType.
const (
	atypIPv4       = 1
	atypDomainName = 3
	atypIPv6       = 4
)

// handshakeTimeout bounds method negotiation and request reading.
const handshakeTimeout = 30 * time.Second

// lookupTimeout bounds .b32/name lookups at the SOCKS layer (on top
// of the netdb's own lookup timeout).
const lookupTimeout = 75 * time.Second

// handleConn runs one SOCKS5 client connection to completion.
func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	tag := c.RemoteAddr().String()
	logf := func(format string, args ...any) {
		if s.Log != nil {
			s.Log.Printf("socks5 %s "+format, append([]any{tag}, args...)...)
		}
	}

	c.SetDeadline(time.Now().Add(handshakeTimeout))
	host, port, err := s.readRequest(c)
	if err != nil {
		logf("request error: %v", err)
		return
	}
	logf("CONNECT %s:%d", host, port)

	dest, err := s.resolve(c, host, logf)
	if err != nil {
		return // reply already sent
	}

	// The stream layer has its own connect timeout (default 60s).
	c.SetDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	stream, err := s.Dialer.Dial(ctx, dest, port)
	if err != nil {
		logf("dial %s: %v", host, err)
		s.reply(c, replyHostUnreachable)
		return
	}

	s.reply(c, replySucceeded)
	logf("connected %s:%d", host, port)
	s.pump(c, stream)
	logf("closed %s:%d", host, port)
}

// readRequest performs method negotiation and reads the CONNECT
// request, returning the target host and port. Unsupported commands
// get their failure reply sent here.
func (s *Server) readRequest(c net.Conn) (string, uint16, error) {
	// ---- method negotiation: VER NMETHODS METHODS ----
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != 5 {
		return "", 0, fmt.Errorf("socks5: version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	// Only NO AUTHENTICATION (0x00) is offered.
	if !containsByte(methods, 0) {
		c.Write([]byte{5, 0xff}) // NO ACCEPTABLE METHODS
		return "", 0, errors.New("socks5: no acceptable auth method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", 0, err
	}

	// ---- request: VER CMD RSV ATYP ----
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", 0, err
	}
	if req[0] != 5 {
		return "", 0, fmt.Errorf("socks5: version %d in request", req[0])
	}
	if req[1] != 1 { // CONNECT only
		s.reply(c, replyCommandNotSupported)
		return "", 0, fmt.Errorf("socks5: command 0x%02x not supported", req[1])
	}

	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypDomainName:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("socks5: zero-length domain")
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	default:
		s.reply(c, replyAddressTypeNotSupport)
		return "", 0, fmt.Errorf("socks5: address type %d", req[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb[:]), nil
}

// isB32Host reports whether host is a .b32.i2p(/.alt) hostname, and
// whether its base32 part is exactly a destination hash (not blinded).
// Reference: NamingService.isB32Host.
func isB32Host(host string) (plain, blinded bool) {
	lc := strings.ToLower(host)
	for _, suffix := range []string{".b32.i2p", ".b32.i2p.alt"} {
		if strings.HasSuffix(lc, suffix) {
			prefix := lc[:len(lc)-len(suffix)]
			return len(prefix) == b32PrefixLen, len(prefix) > b32PrefixLen
		}
	}
	return false, false
}

// resolve turns the requested host into a destination, sending the
// appropriate failure reply on error.
func (s *Server) resolve(c net.Conn, host string, logf func(string, ...any)) (*data.Destination, error) {
	lower := strings.ToLower(host)

	// Local addresses must not be tunneled to I2P.
	// Reference: SOCKS5Server localhost check.
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		host == "127.0.0.1" || host == "[::1]" || strings.HasPrefix(host, "192.168.") {
		s.reply(c, replyConnectionNotAllowed)
		return nil, errors.New("socks5: localhost access not allowed")
	}

	// An I2P destination given inline (base64, 516+ chars).
	if len(host) >= minBase64DestLen {
		dest, err := parseInlineDestination(host)
		if err != nil {
			s.reply(c, replyHostUnreachable)
			return nil, fmt.Errorf("socks5: bad destination: %v", err)
		}
		return dest, nil
	}

	plain, blinded := isB32Host(host)
	if plain || blinded {
		if blinded {
			s.reply(c, replyHostUnreachable)
			return nil, errors.New("socks5: blinded .b32 host not supported")
		}
		dest, err := s.lookup(host, logf)
		if dest == nil && err == nil {
			err = errors.New("not found")
		}
		if err != nil {
			s.reply(c, replyHostUnreachable)
			return nil, fmt.Errorf("socks5: %v", err)
		}
		return dest, nil
	}

	// Plain .i2p name: needs an addressbook entry.
	if strings.HasSuffix(lower, ".i2p") || strings.HasSuffix(lower, ".i2p.alt") {
		dest, err := s.lookup(host, logf)
		if dest == nil && err == nil {
			err = errors.New("not found")
		}
		if err != nil {
			s.reply(c, replyHostUnreachable)
			return nil, fmt.Errorf("socks5: %v", err)
		}
		return dest, nil
	}

	// Not an I2P host at all and no outproxy is configured.
	// Reference: SOCKS5Server "No outproxy configured" branch.
	s.reply(c, replyConnectionNotAllowed)
	return nil, fmt.Errorf("socks5: non-I2P host %q refused (no outproxy)", host)
}

// lookup runs the resolver with the SOCKS-level timeout.
func (s *Server) lookup(host string, logf func(string, ...any)) (*data.Destination, error) {
	if s.Resolver == nil {
		return nil, errors.New("no resolver configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	dest, err := s.Resolver.LookupDestination(ctx, host)
	if err != nil {
		logf("lookup %s: %v", host, err)
	}
	return dest, err
}

// parseInlineDestination decodes a base64 destination string.
func parseInlineDestination(host string) (*data.Destination, error) {
	b, err := data.DecodeI2PBase64(host)
	if err != nil {
		return nil, err
	}
	dest, rest, err := data.ReadDestination(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after destination")
	}
	return &dest, nil
}

// reply sends a SOCKS5 reply with a zero IPv4 bound address.
func (s *Server) reply(c net.Conn, code byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

// pump bridges the local TCP connection and the I2P stream. When the
// local side finishes sending, the stream is half-closed (our CLOSE
// packet); the remote side keeps flowing until it closes too.
func (s *Server) pump(c net.Conn, stream *streaming.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, c)
		stream.Close() // half-close: done sending
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, stream)
		c.Close() // remote side done; stop reading locally too
	}()
	wg.Wait()
}

// containsByte reports whether b appears in list.
func containsByte(list []byte, b byte) bool {
	for _, x := range list {
		if x == b {
			return true
		}
	}
	return false
}

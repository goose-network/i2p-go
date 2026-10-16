package ntcp2

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/i2pcrypto"
)

// ErrTerminated is returned after the peer sent a termination block.
var ErrTerminated = errors.New("ntcp2: connection terminated by peer")

// Conn is an established NTCP2 connection: the Noise-derived ChaChaPoly
// pair plus the SipHash length obfuscation, over a TCP connection.
// Reference: NTCPConnection (data phase).
type Conn struct {
	conn   net.Conn
	reader io.Reader // buffered, may hold read-ahead from the handshake

	send, recv *i2pcrypto.AEAD
	sendSip    *sipState
	recvSip    *sipState

	writeMu sync.Mutex

	// peerSkew is the measured clock skew (valid after handshake).
	peerSkew time.Duration
	// remote is the peer's static key (Bob's for an outbound con).
	remote []byte

	// Terminated is set when the peer sends a termination block.
	Terminated bool
	// TermReason is the termination reason from the peer.
	TermReason int

	// Callback for I2NP messages from received frames.
	// (Set by the router layer; dispatch is via OnI2NP.)
	OnI2NP func(raw []byte)
	// OnRI is called for RouterInfo blocks (netdb intake).
	OnRI func(ri []byte, flood bool)
}

// writeBlocks frames and sends one or more blocks as a single frame.
// Reference: NTCPConnection.sendNTCP2.
func (c *Conn) writeBlocks(blocks []Block) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(EncodeBlocks(blocks))
}

// SendI2NP sends one raw NTCP2-format I2NP message.
func (c *Conn) SendI2NP(raw []byte) error {
	return c.writeBlocks([]Block{I2NPBlock(raw)})
}

// Close sends a termination block and closes the connection.
// Reference: NTCPConnection.close.
func (c *Conn) Close(reason int) error {
	err := c.writeBlocks([]Block{TerminationBlock(reason, 0)})
	cerr := c.conn.Close()
	if err != nil {
		return err
	}
	return cerr
}

// ReadFrame reads, decrypts, and dispatches the next frame. It returns
// nil at EOF after a clean termination.
func (c *Conn) ReadFrame() error {
	payload, err := c.readFrame()
	if err != nil {
		return err
	}
	parsed, err := ParseBlocks(payload, false)
	if err != nil {
		// Non-fatal in the data phase (the Java reference logs and
		// continues); keep the connection alive.
		return nil
	}
	for _, b := range parsed.Blocks {
		switch b.Type {
		case BlockI2NP:
			if c.OnI2NP != nil {
				c.OnI2NP(b.Data)
			}
		case BlockRouterInfo:
			if c.OnRI != nil {
				c.OnRI(b.Data[1:], parsed.Flood)
			}
		case BlockTermination:
			c.Terminated = true
			c.TermReason = parsed.Termination.Reason
			return ErrTerminated
		}
	}
	return nil
}

// PeerSkew returns the measured clock skew.
func (c *Conn) PeerSkew() time.Duration { return c.peerSkew }

// RemoteStatic returns the peer's NTCP2 static key.
func (c *Conn) RemoteStatic() []byte { return append([]byte(nil), c.remote...) }

// newReader wraps conn for buffered reading.
func newReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(conn, BufferSize)
}

// ReadLoop reads frames and dispatches blocks until the connection
// ends. Runs in its own goroutine.
func (c *Conn) ReadLoop() {
	for {
		if err := c.ReadFrame(); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrTerminated) {
				// Network or AEAD failure: close.
				c.conn.Close()
			}
			return
		}
	}
}

// Ping sends a DateTime block (used as a keepalive).
func (c *Conn) Ping() error {
	return c.writeBlocks([]Block{DateTimeBlock(time.Now())})
}

// Write implements io.Writer so Conn can back higher layers directly.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.writeBlocks([]Block{I2NPBlock(p)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// The streaming connection state machine and manager.
//
// Sending side: Write slices data into packets of at most maxPayload
// bytes, each with a fresh sequence number, kept in an unacked map for
// retransmission (RTO timer, exponential backoff, congestion window).
// Receiving side: a reordering buffer (MessageInputStream semantics)
// delivering contiguous data to Read, with cumulative acks (ackThrough
// = highest received) and nacks for the holes.
//
// References: Connection.java, ConnectionPacketHandler.java,
// MessageInputStream.java, ConnectionDataReceiver.java,
// ConnectionManager.java, PacketHandler.java.
package streaming

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

// Tuning defaults. References: Connection.java (MAX_WINDOW_SIZE,
// MAX_RESEND_DELAY), ConnectionOptions.java (INITIAL_WINDOW_SIZE,
// DEFAULT_INITIAL_RTT, INITIAL_RTO, DEFAULT_CONNECT_TIMEOUT,
// DEFAULT_INACTIVITY_TIMEOUT, DEFAULT_MAX_MESSAGE_SIZE).
const (
	defaultMaxWindow     = 24
	initialWindow        = 3
	defaultMaxPacketSize = 1730 // DEFAULT_MAX_MESSAGE_SIZE
	minMessageSize       = 512  // MIN_MESSAGE_SIZE
	initialRTO           = 9 * time.Second
	minRTO               = 100 * time.Millisecond
	maxRTO               = 45 * time.Second
	maxResends           = 8 // DEFAULT_MAX_SENDS
	connectTimeout       = 60 * time.Second
	inactivityTimeout    = 90 * time.Second
	ackDelay             = 200 * time.Millisecond
	writeStallTimeout    = 60 * time.Second
	loopTick             = 100 * time.Millisecond
	// closeLinger: after our close is fully acked we keep the stream
	// around to re-ack the peer's retransmitted CLOSE before removal.
	// Java keeps finished connections in the manager for a grace period
	// for the same reason (ConnectionHandler.removeConnection is delayed).
	closeLinger = 2 * time.Second
)

// Errors surfaced to the socket user.
var (
	// ErrReset means the peer reset the connection.
	ErrReset = errors.New("streaming: connection reset by peer")
	// ErrTimeout covers establish/stall timeouts.
	ErrTimeout = errors.New("streaming: connection timed out")
	// ErrClosed is a write on a closed stream.
	ErrClosed = errors.New("streaming: connection closed")
)

// PacketSender delivers one raw streaming packet to a remote
// destination. Implementations wrap the packet in the I2CP payload
// format (CompressPayload), a DataMessage garlic clove and tunnel
// routing; they must not block for long and must not call back into
// the same Manager synchronously.
type PacketSender interface {
	SendPacket(to *data.Destination, packet []byte, fromPort, toPort uint16) error
}

// Options configures a Manager. Zero values become the defaults.
type Options struct {
	MaxWindow     int           // default 24
	MaxPacketSize int           // our announced/initial payload cap, default 1730
	ConnectWait   time.Duration // default 60s
	InitialRTO    time.Duration // retransmit timeout before an RTT estimate, default 9s
	Now           func() time.Time
}

// Manager owns all streaming connections for our destination.
type Manager struct {
	ourDest  *data.Destination
	ourHash  data.Hash
	signPriv ed25519.PrivateKey
	sender   PacketSender
	opts     Options
	now      func() time.Time

	mu       sync.Mutex
	notify   chan struct{} // closed + replaced on accept-queue changes
	conns    map[uint32]*Stream
	outbound map[uint32]*Stream // by sendStreamID (peer's receive ID)
	acceptQ  []*Stream
	nextID   uint32
}

// NewManager creates a manager for our destination. signPriv is the
// destination's Ed25519 private signing key (packet signatures).
func NewManager(ourDest *data.Destination, signPriv ed25519.PrivateKey, sender PacketSender, opts Options) *Manager {
	if opts.MaxWindow <= 0 {
		opts.MaxWindow = defaultMaxWindow
	}
	if opts.MaxPacketSize <= 0 {
		opts.MaxPacketSize = defaultMaxPacketSize
	}
	if opts.MaxPacketSize > MaxPayloadSize {
		opts.MaxPacketSize = MaxPayloadSize
	}
	if opts.ConnectWait <= 0 {
		opts.ConnectWait = connectTimeout
	}
	if opts.InitialRTO <= 0 {
		opts.InitialRTO = initialRTO
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	m := &Manager{
		ourDest:  ourDest,
		ourHash:  data.DestinationHash(*ourDest),
		signPriv: signPriv,
		sender:   sender,
		opts:     opts,
		now:      now,
		notify:   make(chan struct{}),
		conns:    make(map[uint32]*Stream),
		outbound: make(map[uint32]*Stream),
	}
	return m
}

// OurDestination returns the destination this manager serves.
func (m *Manager) OurDestination() *data.Destination { return m.ourDest }

// Dial opens a connection to a remote destination on the given port
// and blocks until the connection is established (SYN-ACK) or fails.
func (m *Manager) Dial(ctx context.Context, remote *data.Destination, port uint16) (*Stream, error) {
	remoteHash := data.DestinationHash(*remote)
	s := &Stream{
		mgr:              m,
		remote:           cloneDest(remote),
		remoteHash:       remoteHash,
		remotePort:       port,
		localPort:        0,
		window:           initialWindow,
		maxWindow:        m.opts.MaxWindow,
		maxPayload:       m.opts.MaxPacketSize,
		rto:              m.opts.InitialRTO,
		lastSeq:          -1,
		recvHighest:      -1,
		recvHighestReady: -1,
		unacked:          make(map[int64]*txPacket),
		notReady:         make(map[int64][]byte),
		notify:           make(chan struct{}),
		ackKick:          make(chan struct{}, 1),
		done:             make(chan struct{}),
	}
	m.mu.Lock()
	s.receiveStreamID = m.assignIDLocked()
	m.conns[s.receiveStreamID] = s
	m.mu.Unlock()
	go s.loop()

	if err := s.sendSyn(); err != nil {
		s.teardownLocal(err)
		m.removeStream(s)
		return nil, err
	}

	deadline := m.now().Add(m.opts.ConnectWait)
	err := s.waitEstablished(ctx, deadline)
	if err != nil {
		s.teardownLocal(err)
		m.removeStream(s)
		return nil, err
	}
	return s, nil
}

// Accept waits for an inbound connection (a verified SYN).
func (m *Manager) Accept(ctx context.Context) (*Stream, error) {
	for {
		m.mu.Lock()
		if len(m.acceptQ) > 0 {
			s := m.acceptQ[0]
			m.acceptQ = m.acceptQ[1:]
			m.mu.Unlock()
			return s, nil
		}
		ch := m.notify
		m.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// HandleMessage processes one inbound payload in the I2CP format (the
// body of a DataMessage garlic clove, still compressed). Non-streaming
// protocols and unparseable packets are dropped.
func (m *Manager) HandleMessage(gz []byte) {
	plain, proto, fromPort, toPort, err := DecompressPayload(gz)
	if err != nil {
		return
	}
	if proto != 0 && proto != ProtoStreaming {
		return // not for us
	}
	p, err := ParsePacket(plain)
	if err != nil {
		return
	}
	m.dispatch(p, fromPort, toPort)
}

// dispatch routes one parsed packet: by the sendStreamId field against
// our connections' receive IDs (the normal path), then by the
// receiveStreamId field against our outbound connections' send IDs
// (packets sent before the sender learned our ID), then as a new SYN.
// Reference: PacketHandler.receivePacketDirect / receiveUnknownCon.
func (m *Manager) dispatch(p *Packet, fromPort, toPort uint16) {
	m.mu.Lock()
	if p.SendStreamID > 0 {
		if s := m.conns[p.SendStreamID]; s != nil {
			m.mu.Unlock()
			s.handlePacket(p, fromPort, toPort)
			return
		}
		m.mu.Unlock()
		// Unknown ID: usually a dead stream. Pings (ECHO) are still
		// answered — Java handles ECHO before the unknown-ID drop.
		if p.Flags&FlagEcho != 0 {
			m.sendPong(p, fromPort, toPort)
		}
		return
	}
	if s := m.outbound[p.ReceiveStreamID]; s != nil {
		m.mu.Unlock()
		s.handlePacket(p, fromPort, toPort)
		return
	}
	m.mu.Unlock()

	if p.Flags&FlagEcho != 0 {
		return // pong for a ping we never sent
	}
	if p.Flags&FlagSYN != 0 {
		m.receiveSyn(p, fromPort, toPort)
	}
}

// receiveSyn validates a new SYN (signature + the fake-nack anti-spoof
// check) and creates the inbound connection. Reference:
// ConnectionManager.receiveConnection.
func (m *Manager) receiveSyn(p *Packet, fromPort, toPort uint16) {
	from := p.OptionalFrom
	if from == nil || p.Flags&FlagSignatureIncluded == 0 {
		return
	}
	if !p.Verify(nil) {
		return
	}
	// Anti-spoof: 8 "nacks", each 4 bytes of OUR destination hash.
	if len(p.Nacks) == 8 {
		for i := 0; i < 8; i++ {
			if p.Nacks[i] != binary.BigEndian.Uint32(m.ourHash[i*4:]) {
				m.sendResetUnverified(p, from, fromPort, toPort)
				return
			}
		}
	} else if len(p.Nacks) > 0 {
		return // malformed
	}
	if p.ReceiveStreamID == 0 {
		return
	}

	m.mu.Lock()
	if len(m.acceptQ) >= 64 {
		m.mu.Unlock()
		m.sendResetUnverified(p, from, fromPort, toPort)
		return
	}
	s := &Stream{
		mgr:              m,
		inbound:          true,
		remote:           cloneDest(from),
		remoteHash:       data.DestinationHash(*from),
		sendStreamID:     p.ReceiveStreamID,
		remotePort:       fromPort,
		localPort:        toPort,
		window:           initialWindow,
		maxWindow:        m.opts.MaxWindow,
		maxPayload:       m.opts.MaxPacketSize,
		rto:              m.opts.InitialRTO,
		lastSeq:          -1,
		recvHighest:      -1,
		recvHighestReady: -1,
		unacked:          make(map[int64]*txPacket),
		notReady:         make(map[int64][]byte),
		notify:           make(chan struct{}),
		ackKick:          make(chan struct{}, 1),
		done:             make(chan struct{}),
	}
	if p.Flags&FlagMaxPacketSize != 0 {
		if size := int(p.OptionalMaxSize); size >= minMessageSize && size < s.maxPayload {
			s.maxPayload = size
		}
	}
	s.receiveStreamID = m.assignIDLocked()
	m.conns[s.receiveStreamID] = s
	m.outbound[s.sendStreamID] = s
	m.acceptQ = append(m.acceptQ, s)
	notify := m.notify
	m.notify = make(chan struct{})
	close(notify)
	m.mu.Unlock()
	go s.loop()

	// Feed the SYN through the normal path (reassembly + ack state),
	// then send the SYN-ACK: the server's first outbound packet carries
	// FLAG_SYNCHRONIZE + FROM + max size and acks the client's SYN.
	// Reference: ConnectionDataReceiver.buildPacket (isFirst).
	s.handlePacket(p, fromPort, toPort)
	s.mu.Lock()
	var raw []byte
	if !s.sentAny {
		raw, _ = s.buildAndQueueLocked(nil, false)
		s.ackPending = false // the SYN-ACK carries this ack
	}
	remote, fp, tp := s.remote, s.localPort, s.remotePort
	s.mu.Unlock()
	if raw != nil {
		s.sendMu.Lock()
		s.mgr.sender.SendPacket(remote, raw, fp, tp)
		s.sendMu.Unlock()
	}
}

// sendResetUnverified replies RESET to a suspicious SYN. Reference:
// PacketHandler.sendResetUnverified.
func (m *Manager) sendResetUnverified(p *Packet, to *data.Destination, fromPort, toPort uint16) {
	r := &Packet{
		SendStreamID:    p.ReceiveStreamID,
		ReceiveStreamID: p.SendStreamID,
		AckThrough:      p.SequenceNum,
		Flags:           FlagReset | FlagSignatureIncluded | FlagNoAck,
	}
	r.Sign(m.signPriv)
	m.sender.SendPacket(to, r.Encode(), toPort, fromPort)
}

// sendPong answers a ping. Reference: ConnectionManager.receivePing —
// the pong's receiveStreamId echoes the ping's sendStreamId (its ping
// ID), and it is not addressed to any stream.
func (m *Manager) sendPong(p *Packet, fromPort, toPort uint16) {
	from := p.OptionalFrom
	if from == nil {
		return
	}
	pong := &Packet{
		ReceiveStreamID: p.SendStreamID, // echo the ping ID back
		Flags:           FlagEcho | FlagNoAck,
		Payload:         p.Payload,
	}
	m.sender.SendPacket(from, pong.Encode(), toPort, fromPort)
}

// assignIDLocked picks a fresh random receive stream ID (nonzero).
func (m *Manager) assignIDLocked() uint32 {
	for {
		var b [4]byte
		rand.Read(b[:])
		id := binary.BigEndian.Uint32(b[:]) & 0x7fffffff
		if id == 0 {
			continue
		}
		if _, dup := m.conns[id]; dup {
			continue
		}
		return id
	}
}

// registerOutbound adds a stream to the fallback dispatch map once its
// sendStreamID is learned. Called with the stream lock held.
func (m *Manager) registerOutbound(s *Stream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.sendStreamID != 0 {
		m.outbound[s.sendStreamID] = s
	}
}

// removeStream drops a stream from all dispatch maps.
func (m *Manager) removeStream(s *Stream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns, s.receiveStreamID)
	if s.sendStreamID != 0 {
		if cur := m.outbound[s.sendStreamID]; cur == s {
			delete(m.outbound, s.sendStreamID)
		}
	}
	// Purge the accept queue too (closed before accept).
	for i := range m.acceptQ {
		if m.acceptQ[i] == s {
			m.acceptQ = append(m.acceptQ[:i], m.acceptQ[i+1:]...)
			break
		}
	}
}

// Count returns the number of live connections (diagnostics).
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
}

// txPacket is an outbound packet awaiting its ack.
type txPacket struct {
	raw       []byte
	seq       int64
	sends     int
	firstSent time.Time
	lastSent  time.Time
}

// Stream is one streaming connection (both directions).
type Stream struct {
	mgr     *Manager
	inbound bool

	remote     *data.Destination
	remoteHash data.Hash
	remotePort uint16
	localPort  uint16

	// receiveStreamID: our ID (receiveStreamId field of our packets).
	// sendStreamID: the peer's ID (sendStreamId field of our packets).
	receiveStreamID uint32
	sendStreamID    uint32

	mu     sync.Mutex
	notify chan struct{} // closed + replaced on state changes

	resetRecv  bool
	resetErr   error
	closeSent  bool
	closeRecv  bool
	connectErr error

	sentAny    bool
	lastSeq    int64
	unacked    map[int64]*txPacket
	window     int
	maxWindow  int
	maxPayload int
	rtt        time.Duration
	rttVar     time.Duration
	rto        time.Duration
	lastSend   time.Time
	lastRecv   time.Time

	recvHighestReady int64
	recvHighest      int64
	notReady         map[int64][]byte
	recvBuf          []byte

	ackPending  bool
	nextAckTime time.Time

	// ackKick wakes the loop for an immediate ack (buffered-1 latch).
	ackKick  chan struct{}
	finishAt time.Time // when a completed close may tear down

	readDeadline  time.Time
	writeDeadline time.Time

	sendMu sync.Mutex // serializes raw sends
	done   chan struct{}
	closed sync.Once
}

// ---- socket surface ----

// Read reads received data. EOF arrives after the peer's CLOSE once all
// data is reassembled.
func (s *Stream) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.resetErr != nil {
			return 0, s.resetErr
		}
		if len(s.recvBuf) > 0 {
			n := copy(b, s.recvBuf)
			s.recvBuf = s.recvBuf[n:]
			return n, nil
		}
		if s.closeRecv && s.recvHighestReady == s.recvHighest {
			return 0, io.EOF
		}
		if err := s.checkDeadline(s.readDeadline); err != nil {
			return 0, err
		}
		// Wait with the deadline armed, so an idle stream still wakes
		// when the deadline passes rather than blocking indefinitely.
		// On a timeout we loop (not return): the select may have picked
		// the timer even though data arrived with it.
		var err error
		if s.readDeadline.IsZero() {
			err = s.waitNotify()
		} else {
			err = s.waitNotifyUntil(s.readDeadline)
		}
		if err != nil && err != ErrTimeout {
			return 0, err
		}
	}
}

// Write sends data, sliced into maxPayload-sized packets, blocking on
// the congestion window.
func (s *Stream) Write(b []byte) (int, error) {
	total := len(b)
	for len(b) > 0 {
		s.mu.Lock()
		var raw []byte
		var n int
		for {
			if s.resetErr != nil {
				s.mu.Unlock()
				return total - len(b), s.resetErr
			}
			if s.closeSent {
				s.mu.Unlock()
				return total - len(b), ErrClosed
			}
			if s.connectErr != nil {
				s.mu.Unlock()
				return total - len(b), s.connectErr
			}
			if len(s.unacked) < s.window {
				n = min(len(b), s.maxPayload)
				var err error
				raw, err = s.buildAndQueueLocked(b[:n], false)
				if err != nil {
					s.mu.Unlock()
					return total - len(b), err
				}
				break
			}
			if err := s.checkDeadline(s.writeDeadline); err != nil {
				s.mu.Unlock()
				return total - len(b), err
			}
			// Window full: wait for acks (bounded).
			deadline := s.mgr.now().Add(writeStallTimeout)
			if !s.writeDeadline.IsZero() && s.writeDeadline.Before(deadline) {
				deadline = s.writeDeadline
			}
			if err := s.waitNotifyUntil(deadline); err != nil {
				s.mu.Unlock()
				return total - len(b), ErrTimeout
			}
		}
		remote, fp, tp := s.remote, s.localPort, s.remotePort
		s.mu.Unlock()
		s.sendMu.Lock()
		err := s.mgr.sender.SendPacket(remote, raw, fp, tp)
		s.sendMu.Unlock()
		if err != nil {
			return total - len(b), err
		}
		b = b[n:]
	}
	return total, nil
}

// Close sends a CLOSE packet (signed, retransmitted until acked) and
// returns immediately; the stream finishes asynchronously once the peer
// acknowledges or gives up.
func (s *Stream) Close() error {
	var err error
	s.closed.Do(func() {
		s.mu.Lock()
		if !s.closeSent && s.resetErr == nil {
			s.closeSent = true
			var raw []byte
			raw, err = s.buildAndQueueLocked(nil, true)
			remote, fp, tp := s.remote, s.localPort, s.remotePort
			s.mu.Unlock()
			if err == nil {
				s.sendMu.Lock()
				s.mgr.sender.SendPacket(remote, raw, fp, tp)
				s.sendMu.Unlock()
			}
			return
		}
		s.mu.Unlock()
	})
	return err
}

// WaitClosed blocks until the stream fully completes (close acked /
// reset / timeout) or ctx expires. Used by tests and clean shutdowns.
func (s *Stream) WaitClosed(ctx context.Context) error {
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.resetErr != nil {
			return s.resetErr
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalAddr implements net.Conn.
func (s *Stream) LocalAddr() netAddr { return netAddr(s.mgr.ourHash) }

// RemoteAddr implements net.Conn.
func (s *Stream) RemoteAddr() netAddr { return netAddr(s.remoteHash) }

type netAddr data.Hash

func (a netAddr) Network() string { return "i2p" }
func (a netAddr) String() string  { return data.Hash(a).ToI2PBase64()[:12] }

// SetDeadline sets both read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline, s.writeDeadline = t, t
	s.notifyLocked()
	s.mu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.notifyLocked()
	s.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.notifyLocked()
	s.mu.Unlock()
	return nil
}

// ---- helpers used while holding s.mu ----

// notifyLocked wakes all waiters (the channel is closed and replaced).
func (s *Stream) notifyLocked() {
	ch := s.notify
	s.notify = make(chan struct{})
	close(ch)
}

// waitNotify waits for a state change, releasing s.mu while blocked.
func (s *Stream) waitNotify() error { return s.waitNotifyUntil(time.Time{}) }

// waitNotifyUntil waits for a state change or a deadline.
func (s *Stream) waitNotifyUntil(deadline time.Time) error {
	ch := s.notify
	s.mu.Unlock()
	defer s.mu.Lock()
	if deadline.IsZero() {
		<-ch
		return nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		return ErrTimeout
	}
	select {
	case <-ch:
	case <-time.After(d):
		return ErrTimeout
	}
	return nil
}

// checkDeadline returns ErrTimeout if a deadline passed.
func (s *Stream) checkDeadline(t time.Time) error {
	if t.IsZero() {
		return nil
	}
	if s.mgr.now().After(t) {
		return ErrTimeout
	}
	return nil
}

// waitEstablished blocks until both stream IDs are known or the
// connection fails. Reference: Connection.waitForConnect.
func (s *Stream) waitEstablished(ctx context.Context, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.resetErr != nil {
			return s.resetErr
		}
		if s.connectErr != nil {
			return s.connectErr
		}
		if s.sendStreamID != 0 && s.receiveStreamID != 0 {
			return nil
		}
		if err := s.checkDeadline(deadline); err != nil {
			return err
		}
		s.waitNotify()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// ---- packet building ----

// buildAndQueueLocked builds one data (or close) packet, assigns a
// sequence number, stores it for retransmission and returns the wire
// bytes. Reference: ConnectionDataReceiver.buildPacket.
func (s *Stream) buildAndQueueLocked(payload []byte, close bool) ([]byte, error) {
	first := !s.sentAny
	s.sentAny = true
	s.lastSeq++
	seq := s.lastSeq

	p := &Packet{
		SendStreamID:    s.sendStreamID,
		ReceiveStreamID: s.receiveStreamID,
		SequenceNum:     seq,
	}
	if first {
		p.Flags = FlagSYN | FlagFromIncluded | FlagSignatureIncluded | FlagMaxPacketSize
		our := cloneDest(s.mgr.ourDest)
		p.OptionalFrom = our
		p.OptionalMaxSize = uint16(s.maxPayload)
		if !s.inbound {
			// Anti-spoof fake nacks: 4-byte words of the REMOTE's hash.
			h := s.remoteHash
			p.Nacks = []uint32{
				binary.BigEndian.Uint32(h[0:]), binary.BigEndian.Uint32(h[4:]),
				binary.BigEndian.Uint32(h[8:]), binary.BigEndian.Uint32(h[12:]),
				binary.BigEndian.Uint32(h[16:]), binary.BigEndian.Uint32(h[20:]),
				binary.BigEndian.Uint32(h[24:]), binary.BigEndian.Uint32(h[28:]),
			}
		}
	}
	if s.sendStreamID == 0 {
		// We don't know their ID yet (our SYN, or early data).
		p.Flags |= FlagNoAck
		p.AckThrough = noAckThrough
	} else {
		p.AckThrough = s.recvHighest
		if !first {
			p.Nacks = s.recvNacksLocked()
		}
	}
	if close {
		// Java's shouldSign() signs every CLOSE packet.
		p.Flags |= FlagClose | FlagSignatureIncluded
	} else if len(payload) > 0 {
		// Ask for fast acks (Java's unchoke behavior: delay 0).
		p.Flags |= FlagDelayRequested
	}
	p.Payload = payload
	if p.Flags&FlagSignatureIncluded != 0 {
		p.Sign(s.mgr.signPriv)
	}
	raw := p.Encode()
	now := s.mgr.now()
	s.unacked[seq] = &txPacket{raw: raw, seq: seq, sends: 1, firstSent: now, lastSent: now}
	s.lastSend = now
	return raw, nil
}

// buildAckLocked builds an ack-only packet (sequence 0, no payload).
func (s *Stream) buildAckLocked() *Packet {
	p := &Packet{
		SendStreamID:    s.sendStreamID,
		ReceiveStreamID: s.receiveStreamID,
		SequenceNum:     0,
		AckThrough:      s.recvHighest,
		Nacks:           s.recvNacksLocked(),
	}
	return p
}

// recvNacksLocked lists missing sequence numbers between the highest
// contiguous and the highest received. Reference:
// MessageInputStream.locked_getNacks.
func (s *Stream) recvNacksLocked() []uint32 {
	var nacks []uint32
	for i := s.recvHighestReady + 1; i < s.recvHighest; i++ {
		if _, ok := s.notReady[i]; !ok {
			nacks = append(nacks, uint32(i))
		}
	}
	return nacks
}

// sendSyn sends the first packet of a client connection.
func (s *Stream) sendSyn() error {
	s.mu.Lock()
	raw, err := s.buildAndQueueLocked(nil, false)
	remote, fp, tp := s.remote, s.localPort, s.remotePort
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.mgr.sender.SendPacket(remote, raw, fp, tp)
}

// ---- receive path ----

// handlePacket processes one inbound packet for this connection.
// References: PacketHandler.receiveKnownCon (ID matching),
// ConnectionPacketHandler.receivePacket (the state machine).
func (s *Stream) handlePacket(p *Packet, fromPort, toPort uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.mgr.now()
	s.lastRecv = now

	// RESET: verify if signed, then tear down.
	if p.Flags&FlagReset != 0 {
		if p.Flags&FlagSignatureIncluded != 0 {
			spk := s.remoteSPK()
			if spk == nil || !p.Verify(spk) {
				return // forged
			}
		}
		s.resetRecv = true
		s.teardownLocked(ErrReset)
		return
	}

	// Pings on an established stream get a pong (Java answers pings).
	if p.Flags&FlagEcho != 0 {
		return
	}

	// Signed packets must verify against the known remote. Java only
	// verifies when required (SYN/CLOSE/SIGNATURE_INCLUDED); in practice
	// those are exactly the packets that carry signatures, so verify
	// everything that does.
	if p.Flags&FlagSignatureIncluded != 0 {
		spk := s.remoteSPK()
		if spk == nil || !p.Verify(spk) {
			return // forged or unknown signer
		}
		if p.OptionalFrom != nil && !s.remoteHash.Equal(data.DestinationHash(*p.OptionalFrom)) {
			return // wrong destination
		}
	} else if p.Flags&FlagSYN != 0 && s.sendStreamID != 0 {
		// An unsigned SYN once established: not authentic.
		return
	}

	// Learn our send ID from the peer's SYN(-ACK).
	if s.sendStreamID == 0 && p.Flags&FlagSYN != 0 && p.ReceiveStreamID != 0 {
		s.sendStreamID = p.ReceiveStreamID
		s.mgr.registerOutbound(s)
		s.notifyLocked()
	}

	// Packets must be addressed to our stream once established.
	if s.sendStreamID != 0 && p.ReceiveStreamID != 0 && s.sendStreamID != p.ReceiveStreamID {
		return // wrong stream (Java sends a reset; we just drop)
	}

	// Data.
	isNew := false
	if p.SequenceNum > 0 || p.Flags&FlagSYN != 0 {
		isNew = s.messageReceivedLocked(p.SequenceNum, p.Payload)
	}

	// Schedule an ack for new data (and duplicates: dup-ack).
	if isNew || p.SequenceNum > 0 || len(p.Payload) > 0 || p.Flags&FlagSYN != 0 {
		immediate := p.Flags&FlagDelayRequested != 0 && p.OptionalDelay == 0
		s.scheduleAckLocked(now, immediate)
	}

	// Process acks (skip the ACK-0 inside a SYN that hasn't seen our
	// messages; Java: fastAck = false for SYN w/ sendStreamId <= 0).
	if !(p.Flags&FlagSYN != 0 && p.SendStreamID == 0) {
		s.processAckLocked(p, now)
	}

	// Peer's max packet size: shrink our sends if they ask.
	if p.Flags&FlagMaxPacketSize != 0 && !(s.inbound && p.Flags&FlagSYN != 0) {
		if size := int(p.OptionalMaxSize); size >= minMessageSize && size < s.maxPayload {
			s.maxPayload = size
		}
	}

	// CLOSE — after the data has been queued.
	if p.Flags&FlagClose != 0 {
		if !s.closeRecv {
			s.closeRecv = true
			s.notifyLocked()
		}
	}
	s.notifyLocked()
}

// messageReceivedLocked feeds the reassembly buffer. Reference:
// MessageInputStream.messageReceived.
func (s *Stream) messageReceivedLocked(seq int64, payload []byte) bool {
	if seq <= s.recvHighestReady {
		return false // duplicate
	}
	if seq > s.recvHighest {
		s.recvHighest = seq
	}
	if seq == s.recvHighestReady+1 {
		if len(payload) > 0 {
			s.recvBuf = append(s.recvBuf, payload...)
		}
		s.recvHighestReady = seq
		for {
			next := s.recvHighestReady + 1
			blk, ok := s.notReady[next]
			if !ok {
				break
			}
			delete(s.notReady, next)
			if len(blk) > 0 {
				s.recvBuf = append(s.recvBuf, blk...)
			}
			s.recvHighestReady = next
		}
		s.notifyLocked()
	} else {
		// Out of order: hold it. Payload copied: the packet buffer is
		// reused by the transport.
		s.notReady[seq] = append([]byte(nil), payload...)
	}
	return true
}

// processAckLocked removes acked packets from the unacked map, updates
// RTT/RTO and grows the window. References: Connection.ackPackets,
// ConnectionPacketHandler.ack, adjustWindow.
func (s *Stream) processAckLocked(p *Packet, now time.Time) {
	// Java: no ack processing until all four stream IDs are known.
	if s.sendStreamID == 0 || s.receiveStreamID == 0 ||
		p.SendStreamID == 0 || p.ReceiveStreamID == 0 {
		return
	}
	if p.Flags&FlagNoAck != 0 {
		return // packet acks nothing (Java: ackThrough = -1)
	}
	if p.AckThrough < 0 {
		return
	}
	nacked := make(map[int64]bool, len(p.Nacks))
	for _, n := range p.Nacks {
		nacked[int64(n)] = true
	}
	acked := 0
	var highestRTT time.Duration
	for id, tp := range s.unacked {
		if id <= p.AckThrough && !nacked[id] {
			delete(s.unacked, id)
			acked++
			if tp.sends == 1 {
				if d := now.Sub(tp.firstSent); d > highestRTT {
					highestRTT = d
				}
			}
		}
	}
	if acked > 0 {
		if highestRTT > 0 {
			s.updateRTTLocked(highestRTT)
		}
		// Slow start / additive increase (never decrease here).
		if s.window < s.maxWindow {
			s.window++
		}
		s.notifyLocked() // writers may proceed
	}
	// Fast retransmit: nacked packets that have been outstanding a
	// while get resent without waiting for the full RTO.
	for id, tp := range s.unacked {
		if nacked[id] && now.Sub(tp.lastSent) > s.rto/2 {
			s.resendLocked(tp, now)
		}
	}
}

// updateRTTLocked updates the RTT estimate and the RTO (RFC 6298).
// Reference: ConnectionOptions.updateRTT / computeRTO.
func (s *Stream) updateRTTLocked(sample time.Duration) {
	if sample <= 0 || sample > 60*time.Second {
		return
	}
	if s.rtt == 0 {
		s.rtt = sample
		s.rttVar = sample / 2
	} else {
		err := sample - s.rtt
		if err < 0 {
			err = -err
		}
		s.rtt = (7*s.rtt + sample) / 8
		s.rttVar = (3*s.rttVar + err) / 4
	}
	rto := s.rtt + 4*s.rttVar
	if rto < minRTO {
		rto = minRTO
	}
	if rto > maxRTO {
		rto = maxRTO
	}
	s.rto = rto
}

// scheduleAckLocked defers an ack so several packets can be acked at
// once. Reference: ConnectionPacketHandler ack scheduling.
func (s *Stream) scheduleAckLocked(now time.Time, immediate bool) {
	if s.ackPending {
		if immediate && now.Before(s.nextAckTime) {
			s.nextAckTime = now
		}
		if immediate {
			s.kickAckLocked()
		}
		return
	}
	s.ackPending = true
	delay := ackDelay
	if immediate {
		delay = 0
		s.kickAckLocked()
	}
	s.nextAckTime = now.Add(delay)
}

// kickAckLocked wakes the loop goroutine to send a pending immediate
// ack without waiting for the ticker.
func (s *Stream) kickAckLocked() {
	select {
	case s.ackKick <- struct{}{}:
	default:
	}
}

// ---- send-side background loop ----

// loop drives retransmissions, deferred acks, keepalives and teardown.
// It exits when the stream finishes (close acked / reset / timeout).
func (s *Stream) loop() {
	ticker := time.NewTicker(loopTick)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-s.ackKick:
		case <-ticker.C:
		}
		var jobs [][]byte
		func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.resetErr != nil {
				return
			}
			now := s.mgr.now()

			// Deferred ack (piggybacked fields were already set when data
			// packets were built; this is a standalone ack).
			if s.ackPending && !now.Before(s.nextAckTime) {
				s.ackPending = false
				if p := s.buildAckLocked(); p != nil {
					jobs = append(jobs, p.Encode())
				}
			}

			// Retransmissions.
			for _, tp := range s.unacked {
				if now.Sub(tp.lastSent) >= s.rto {
					// Java: after several CLOSE resends with the peer
					// gone quiet, give up instead of retransmitting for
					// minutes.
					if tp.sends >= 3 && s.closeRecv && len(s.unacked) <= 1 &&
						len(s.notReady) == 0 {
						s.teardownLocked(nil)
						return
					}
					if tp.sends > maxResends {
						s.resetRecv = true
						s.teardownLocked(fmt.Errorf("streaming: no ack after %d sends of seq %d", tp.sends, tp.seq))
						return
					}
					s.resendLocked(tp, now)
					jobs = append(jobs, tp.raw)
				}
			}

			// Inactivity: keepalive-send (Java default action) — but if
			// the peer has been silent twice the timeout, give up.
			if !s.lastRecv.IsZero() && now.Sub(s.lastRecv) > 2*inactivityTimeout {
				s.teardownLocked(ErrTimeout)
				return
			}

			// Finished: close sent + received + all data acked. Linger a
			// moment so the peer's retransmitted CLOSE gets re-acked
			// (Java keeps finished connections around for a grace
			// period), then tear down.
			if s.closeSent && s.closeRecv && len(s.unacked) == 0 {
				if s.finishAt.IsZero() {
					s.finishAt = now.Add(closeLinger)
				} else if !now.Before(s.finishAt) {
					s.teardownLocked(nil)
				}
				return
			}
		}()
		if len(jobs) > 0 {
			s.sendMu.Lock()
			for _, raw := range jobs {
				s.mgr.sender.SendPacket(s.remote, raw, s.localPort, s.remotePort)
			}
			s.sendMu.Unlock()
		}
	}
}

// resendLocked records a retransmission and collapses the window.
// Reference: Connection.ResendPacketEvent.retransmit (congestion).
func (s *Stream) resendLocked(tp *txPacket, now time.Time) {
	tp.sends++
	tp.lastSent = now
	s.rto *= 2
	if s.rto > maxRTO {
		s.rto = maxRTO
	}
	// Congestion: drop to a minimal window and restart slow start.
	s.window = 1
}

// teardownLocked finalizes the stream: wakes all waiters and stops the
// loop. err becomes the error for pending reads/writes (nil = normal
// end after a completed close).
func (s *Stream) teardownLocal(err error) {
	s.mu.Lock()
	s.teardownLocked(err)
	s.mu.Unlock()
}

func (s *Stream) teardownLocked(err error) {
	if s.resetErr == nil {
		if err == nil && s.resetRecv {
			err = ErrReset
		}
		s.resetErr = err
	}
	s.notifyLocked()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.mgr.removeStream(s)
}

// remoteSPK returns the remote destination's Ed25519 public key.
func (s *Stream) remoteSPK() ed25519.PublicKey {
	if s.remote == nil || s.remote.SigType != data.SigEdDSA_SHA512_Ed25519 {
		return nil
	}
	if len(s.remote.SigningKey) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(s.remote.SigningKey)
}

// cloneDest copies a destination (packets alias their buffers).
func cloneDest(d *data.Destination) *data.Destination {
	c := &data.Destination{
		EncKey:     append([]byte(nil), d.EncKey...),
		SigningKey: append([]byte(nil), d.SigningKey...),
		SigType:    d.SigType,
		EncType:    d.EncType,
		Pad:        append([]byte(nil), d.Pad...),
	}
	return c
}

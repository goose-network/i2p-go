// Fragment reassembly: collecting the fragments of an I2NP message
// that arrived in multiple tunnel messages, once the endpoint has
// decrypted and parsed them.
//
// At the inbound endpoint, the reassembled message is a complete I2NP
// message (16-byte header). At the outbound endpoint, the payload is
// the raw {type, body} of an "unknown" message (the OBEP parses only
// the first byte and forwards the rest).
//
// Reference: FragmentHandler.java, FragmentedMessage.java.
package tunnel

import (
	"fmt"
	"sync"
	"time"
)

// Defrag limits. Reference: FragmentHandler.java.
const (
	MaxConcurrentFragmented = 128
	MaxDefragmentTime       = 45 * time.Second
)

// CompleteMessage is a reassembled message ready for delivery.
type CompleteMessage struct {
	// Data is the full I2NP message (16-byte header) at the IBEP, or
	// {type byte, body} at the OBEP.
	Data []byte
	// ToRouter/ToTunnel are the OBEP delivery target (from the first
	// fragment's instructions).
	ToRouter []byte
	ToTunnel uint32
	// MessageID is the fragment assembly key.
	MessageID uint32
}

// Reassembler tracks partially received fragmented messages.
// Reference: FragmentHandler.
type Reassembler struct {
	mu       sync.Mutex
	partial  map[uint32]*partialMessage
	received map[uint32]time.Time
}

type partialMessage struct {
	parts     map[int][]byte
	toRouter  []byte
	toTunnel  uint32
	fragTotal int
	firstAt   time.Time
	lastSize  int
}

// NewReassembler creates an empty reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{
		partial:  make(map[uint32]*partialMessage),
		received: make(map[uint32]time.Time),
	}
}

// Receive processes a parsed fragment and returns a complete message
// if this fragment finishes it. Reference: FragmentHandler.
// receiveFragment / receiveInitialFragment / receiveSubsequentFragment.
func (r *Reassembler) Receive(f *Fragment) (*CompleteMessage, error) {
	if !f.Fragmented && !f.Subsequent {
		// Whole message in one fragment.
		return &CompleteMessage{
			Data:      f.Payload,
			ToRouter:  f.ToRouter,
			ToTunnel:  f.ToTunnel,
			MessageID: f.MessageID,
		}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire()
	if len(r.partial) >= MaxConcurrentFragmented {
		if _, ok := r.partial[f.MessageID]; !ok {
			return nil, fmt.Errorf("tunnel: too many fragmented messages")
		}
	}
	m, ok := r.partial[f.MessageID]
	if !ok {
		if f.Subsequent {
			return nil, fmt.Errorf("tunnel: subsequent fragment without first")
		}
		m = &partialMessage{
			parts:    make(map[int][]byte),
			toRouter: f.ToRouter,
			toTunnel: f.ToTunnel,
			firstAt:  time.Now(),
		}
		r.partial[f.MessageID] = m
	}
	if f.Subsequent {
		if _, dup := m.parts[f.FragNum]; dup {
			return nil, fmt.Errorf("tunnel: duplicate fragment %d", f.FragNum)
		}
		m.parts[f.FragNum] = f.Payload
		if f.IsLast {
			m.fragTotal = f.FragNum + 1
			m.lastSize = len(f.Payload)
		}
	} else {
		m.parts[0] = f.Payload
		if !f.Fragmented {
			// Java marks a non-fragmented message delivered straight
			// from receiveInitialFragment; we handled that above.
		}
	}
	if m.fragTotal == 0 {
		return nil, nil
	}
	for i := 0; i < m.fragTotal; i++ {
		if _, ok := m.parts[i]; !ok {
			return nil, nil
		}
	}
	// All parts present: assemble in order.
	total := 0
	for i := 0; i < m.fragTotal; i++ {
		total += len(m.parts[i])
	}
	data := make([]byte, 0, total)
	for i := 0; i < m.fragTotal; i++ {
		data = append(data, m.parts[i]...)
	}
	delete(r.partial, f.MessageID)
	return &CompleteMessage{
		Data:      data,
		ToRouter:  m.toRouter,
		ToTunnel:  m.toTunnel,
		MessageID: f.MessageID,
	}, nil
}

// expire drops stale partial messages. Reference:
// FragmentHandler.RemoveFailed.
func (r *Reassembler) expire() {
	now := time.Now()
	for id, m := range r.partial {
		if now.Sub(m.firstAt) > MaxDefragmentTime {
			delete(r.partial, id)
		}
	}
}

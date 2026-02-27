package audit

import (
	"fmt"
	"io"
	"log"
	"sync"
)

const (
	// DefaultMaxObservers is the default cap when StreamerConfig.MaxObservers is zero.
	DefaultMaxObservers = 10

	// observerChanSize is the per-observer channel buffer.
	// Frames dropped when the channel is full — session is never slowed down.
	observerChanSize = 64

	// replayBufSize is the size of the ring buffer sent to new observers
	// joining mid-session so they have immediate context.
	replayBufSize = 4 * 1024 // 4 KB
)

// StreamerConfig holds tunable parameters for a Streamer.
type StreamerConfig struct {
	// MaxObservers is the maximum number of concurrent observers per session.
	// 0 means DefaultMaxObservers.
	MaxObservers int
}

// Streamer broadcasts session output to zero or more observers in real time.
//
// It implements io.Writer — wire it into bridge.Run() via io.MultiWriter
// alongside the Recorder so every stdout/stderr frame is fanned out.
//
// Each observer gets its own goroutine and buffered channel so a slow
// observer never blocks the SSH session. Frames are dropped (not queued
// indefinitely) when an observer cannot keep up.
//
// New observers joining mid-session receive the last 4 KB of output
// as a replay buffer before the live stream begins.
//
// Safe for concurrent use.
type Streamer struct {
	mu           sync.RWMutex
	observers    map[uint64]*observer
	nextID       uint64
	maxObservers int

	// replayBuf is a ring buffer of the last replayBufSize bytes.
	replayBuf []byte
	replayPos int // write position in ring
	replayLen int // how many bytes have been written (capped at replayBufSize)
}

// observer holds the per-observer state.
type observer struct {
	id   uint64
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

// NewStreamer creates a Streamer with the given config.
func NewStreamer(cfg StreamerConfig) *Streamer {
	max := cfg.MaxObservers
	if max <= 0 {
		max = DefaultMaxObservers
	}
	return &Streamer{
		observers:    make(map[uint64]*observer),
		maxObservers: max,
		replayBuf:    make([]byte, replayBufSize),
	}
}

// Write implements io.Writer. Called by bridge.Run() with each stdout/stderr
// frame. Fans the frame out to all current observers asynchronously.
// Never blocks — slow observers drop frames.
func (s *Streamer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	frame := make([]byte, len(p))
	copy(frame, p)

	s.mu.Lock()
	s.appendReplay(frame)
	for _, obs := range s.observers {
		select {
		case obs.ch <- frame:
		default:
			// Observer channel full — drop frame, keep session moving.
			log.Printf("[STREAMER] observer %d too slow, frame dropped", obs.id)
		}
	}
	s.mu.Unlock()

	return len(p), nil
}

// Subscribe registers w as a new observer. The observer immediately receives
// a replay of the last 4 KB of session output, then live frames.
//
// Returns an unsubscribe function — the caller must call it when the
// observer disconnects (e.g. WebSocket closed) to release resources.
//
// Returns an error if the observer limit has been reached.
func (s *Streamer) Subscribe(w io.Writer) (unsubscribe func(), err error) {
	s.mu.Lock()

	if len(s.observers) >= s.maxObservers {
		s.mu.Unlock()
		return nil, fmt.Errorf("streamer: observer limit reached (%d)", s.maxObservers)
	}

	id := s.nextID
	s.nextID++

	obs := &observer{
		id:   id,
		ch:   make(chan []byte, observerChanSize),
		done: make(chan struct{}),
	}

	// Snapshot the replay buffer while holding the lock.
	replay := s.replaySnapshot()

	s.observers[id] = obs
	count := len(s.observers)
	s.mu.Unlock()

	log.Printf("[STREAMER] observer %d subscribed (%d/%d)", id, count, s.maxObservers)

	// Send replay then pump live frames in a dedicated goroutine.
	go func() {
		// Replay — send buffered context to the new observer.
		if len(replay) > 0 {
			if _, err := w.Write(replay); err != nil {
				log.Printf("[STREAMER] observer %d replay write error: %v", id, err)
				obs.close()
				return
			}
		}

		for {
			select {
			case frame := <-obs.ch:
				if _, err := w.Write(frame); err != nil {
					log.Printf("[STREAMER] observer %d write error: %v", id, err)
					return
				}
			case <-obs.done:
				return
			}
		}
	}()

	unsubscribe = func() {
		obs.close()
		s.mu.Lock()
		delete(s.observers, id)
		s.mu.Unlock()
		log.Printf("[STREAMER] observer %d unsubscribed", id)
	}

	return unsubscribe, nil
}

// ObserverCount returns the number of currently active observers.
func (s *Streamer) ObserverCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.observers)
}

// Close unsubscribes all observers and releases resources.
// Called when the SSH session ends.
func (s *Streamer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, obs := range s.observers {
		obs.close()
		delete(s.observers, id)
	}
	return nil
}

// appendReplay writes p into the ring buffer. Must be called with s.mu held.
func (s *Streamer) appendReplay(p []byte) {
	for _, b := range p {
		s.replayBuf[s.replayPos] = b
		s.replayPos = (s.replayPos + 1) % replayBufSize
		if s.replayLen < replayBufSize {
			s.replayLen++
		}
	}
}

// replaySnapshot returns a copy of the current replay buffer contents
// in chronological order. Must be called with s.mu held.
func (s *Streamer) replaySnapshot() []byte {
	if s.replayLen == 0 {
		return nil
	}
	out := make([]byte, s.replayLen)
	if s.replayLen < replayBufSize {
		// Buffer not yet full — data starts at index 0.
		copy(out, s.replayBuf[:s.replayLen])
	} else {
		// Buffer full — oldest byte is at replayPos.
		n := copy(out, s.replayBuf[s.replayPos:])
		copy(out[n:], s.replayBuf[:s.replayPos])
	}
	return out
}

// close signals the observer goroutine to stop. Idempotent.
func (o *observer) close() {
	o.once.Do(func() { close(o.done) })
}

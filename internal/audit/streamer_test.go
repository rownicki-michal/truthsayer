package audit

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

func newStreamer(maxObservers int) *Streamer {
	return NewStreamer(StreamerConfig{MaxObservers: maxObservers})
}

// subscribeBuffer subscribes a safeBuffer as an observer and returns
// the buffer and the unsubscribe function.
func subscribeBuffer(t *testing.T, s *Streamer) (*safeBuffer, func()) {
	t.Helper()
	buf := &safeBuffer{}
	unsub, err := s.Subscribe(buf)
	require.NoError(t, err)
	return buf, unsub
}

// waitFor polls cond every 5ms until it returns true or timeout is reached.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// =============================================================================
// NewStreamer
// =============================================================================

func TestNewStreamer_DefaultMaxObservers(t *testing.T) {
	s := NewStreamer(StreamerConfig{})
	assert.Equal(t, DefaultMaxObservers, s.maxObservers)
}

func TestNewStreamer_CustomMaxObservers(t *testing.T) {
	s := newStreamer(25)
	assert.Equal(t, 25, s.maxObservers)
}

func TestNewStreamer_ZeroObserversOnStart(t *testing.T) {
	s := newStreamer(10)
	assert.Equal(t, 0, s.ObserverCount())
}

// =============================================================================
// Write
// =============================================================================

func TestWrite_EmptyFrameIsNoop(t *testing.T) {
	s := newStreamer(10)
	n, err := s.Write([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestWrite_ReturnsLenOfInput(t *testing.T) {
	s := newStreamer(10)
	n, err := s.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

func TestWrite_WithNoObserversDoesNotBlock(t *testing.T) {
	s := newStreamer(10)

	done := make(chan struct{})
	go func() {
		s.Write([]byte("data")) //nolint:errcheck
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Write blocked with no observers")
	}
}

func TestWrite_FrameReachesObserver(t *testing.T) {
	s := newStreamer(10)
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	_, err := s.Write([]byte("hello"))
	require.NoError(t, err)

	waitFor(t, time.Second, func() bool {
		return buf.String() == "hello"
	})
}

func TestWrite_MultipleFramesReachObserverInOrder(t *testing.T) {
	s := newStreamer(10)
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	s.Write([]byte("one"))   //nolint:errcheck
	s.Write([]byte("two"))   //nolint:errcheck
	s.Write([]byte("three")) //nolint:errcheck

	waitFor(t, time.Second, func() bool {
		return buf.Len() == len("onetwothree")
	})
	assert.Equal(t, "onetwothree", buf.String())
}

func TestWrite_DoesNotMutateOriginalSlice(t *testing.T) {
	s := newStreamer(10)
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	original := []byte("hello")
	s.Write(original) //nolint:errcheck
	original[0] = 'X' // mutate after Write

	waitFor(t, time.Second, func() bool {
		return buf.Len() > 0
	})
	// Observer should have received original "hello", not "Xello"
	assert.Equal(t, "hello", buf.String())
}

// =============================================================================
// Subscribe
// =============================================================================

func TestSubscribe_IncrementsObserverCount(t *testing.T) {
	s := newStreamer(10)
	_, unsub := subscribeBuffer(t, s)
	defer unsub()

	assert.Equal(t, 1, s.ObserverCount())
}

func TestSubscribe_UnsubscribeDecrementsObserverCount(t *testing.T) {
	s := newStreamer(10)
	_, unsub := subscribeBuffer(t, s)

	unsub()

	assert.Equal(t, 0, s.ObserverCount())
}

func TestSubscribe_UnsubscribeIsIdempotent(t *testing.T) {
	s := newStreamer(10)
	_, unsub := subscribeBuffer(t, s)

	unsub()
	assert.NotPanics(t, unsub, "second unsubscribe should not panic")
	assert.Equal(t, 0, s.ObserverCount())
}

func TestSubscribe_ReturnsErrorWhenLimitReached(t *testing.T) {
	s := newStreamer(2)

	_, unsub1 := subscribeBuffer(t, s)
	defer unsub1()
	_, unsub2 := subscribeBuffer(t, s)
	defer unsub2()

	_, err := s.Subscribe(&safeBuffer{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "observer limit reached")
}

func TestSubscribe_AllowsNewObserverAfterUnsubscribe(t *testing.T) {
	s := newStreamer(1)

	_, unsub := subscribeBuffer(t, s)
	unsub()

	_, err := s.Subscribe(&safeBuffer{})
	assert.NoError(t, err, "should allow new observer after previous unsubscribed")
}

// =============================================================================
// Fan-out — multiple observers
// =============================================================================

func TestFanOut_FrameReachesAllObservers(t *testing.T) {
	s := newStreamer(10)

	buf1, unsub1 := subscribeBuffer(t, s)
	buf2, unsub2 := subscribeBuffer(t, s)
	buf3, unsub3 := subscribeBuffer(t, s)
	defer unsub1()
	defer unsub2()
	defer unsub3()

	s.Write([]byte("broadcast")) //nolint:errcheck

	waitFor(t, time.Second, func() bool {
		return buf1.String() == "broadcast" &&
			buf2.String() == "broadcast" &&
			buf3.String() == "broadcast"
	})
}

func TestFanOut_SlowObserverDoesNotBlockOthers(t *testing.T) {
	s := newStreamer(10)

	// Slow observer — blocks on Write.
	slowWriter := &blockingWriter{block: make(chan struct{})}
	_, err := s.Subscribe(slowWriter)
	require.NoError(t, err)

	// Fast observer — should receive data normally.
	fastBuf, unsub := subscribeBuffer(t, s)
	defer unsub()

	s.Write([]byte("data")) //nolint:errcheck

	waitFor(t, time.Second, func() bool {
		return fastBuf.String() == "data"
	})

	// Unblock slow observer so goroutine can exit cleanly.
	close(slowWriter.block)
}

func TestFanOut_UnsubscribedObserverReceivesNoMoreFrames(t *testing.T) {
	s := newStreamer(10)

	buf, unsub := subscribeBuffer(t, s)

	s.Write([]byte("before")) //nolint:errcheck
	waitFor(t, time.Second, func() bool {
		return buf.String() == "before"
	})

	unsub()

	s.Write([]byte("after")) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, "before", buf.String(),
		"unsubscribed observer should not receive frames after unsubscribe")
}

// =============================================================================
// Replay buffer
// =============================================================================

func TestReplay_NewObserverReceivesPreviousOutput(t *testing.T) {
	s := newStreamer(10)

	s.Write([]byte("existing output")) //nolint:errcheck

	// Subscribe after data was written.
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	waitFor(t, time.Second, func() bool {
		return bytes.Contains(buf.Bytes(), []byte("existing output"))
	})
}

func TestReplay_NewObserverReceivesReplayThenLive(t *testing.T) {
	s := newStreamer(10)

	s.Write([]byte("replay-data")) //nolint:errcheck

	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	s.Write([]byte("live-data")) //nolint:errcheck

	waitFor(t, time.Second, func() bool {
		content := buf.String()
		return bytes.Contains([]byte(content), []byte("replay-data")) &&
			bytes.Contains([]byte(content), []byte("live-data"))
	})

	content := buf.String()
	assert.Contains(t, content, "replay-data")
	assert.Contains(t, content, "live-data")
}

func TestReplay_EmptySessionSendsNoReplay(t *testing.T) {
	s := newStreamer(10)

	// Subscribe before any data is written.
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	s.Write([]byte("first")) //nolint:errcheck

	waitFor(t, time.Second, func() bool {
		return buf.String() == "first"
	})
	// Only live data, no replay prefix.
	assert.Equal(t, "first", buf.String())
}

func TestReplay_BufferCappedAt4KB(t *testing.T) {
	s := newStreamer(10)

	// Write 8KB — only last 4KB should be replayed.
	first4KB := bytes.Repeat([]byte("A"), replayBufSize)
	second4KB := bytes.Repeat([]byte("B"), replayBufSize)

	s.Write(first4KB)  //nolint:errcheck
	s.Write(second4KB) //nolint:errcheck

	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	waitFor(t, time.Second, func() bool {
		return buf.Len() >= replayBufSize
	})

	replay := buf.Bytes()[:replayBufSize]
	assert.Equal(t, second4KB, replay,
		"replay should contain only the last 4KB")
}

// =============================================================================
// Close
// =============================================================================

func TestClose_RemovesAllObservers(t *testing.T) {
	s := newStreamer(10)

	subscribeBuffer(t, s)
	subscribeBuffer(t, s)
	subscribeBuffer(t, s)

	require.Equal(t, 3, s.ObserverCount())

	err := s.Close()
	assert.NoError(t, err)
	assert.Equal(t, 0, s.ObserverCount())
}

func TestClose_IsIdempotent(t *testing.T) {
	s := newStreamer(10)
	subscribeBuffer(t, s)

	assert.NoError(t, s.Close())
	assert.NotPanics(t, func() { s.Close() }) //nolint:errcheck
}

func TestClose_WriteAfterCloseDoesNotPanic(t *testing.T) {
	s := newStreamer(10)
	s.Close() //nolint:errcheck

	assert.NotPanics(t, func() {
		s.Write([]byte("after close")) //nolint:errcheck
	})
}

// =============================================================================
// Concurrency
// =============================================================================

func TestConcurrent_WriteAndSubscribe_NoRace(t *testing.T) {
	s := newStreamer(20)
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.Write([]byte(fmt.Sprintf("frame-%d", i))) //nolint:errcheck
		}(i)
	}

	// Concurrent subscribers.
	unsubFns := make([]func(), 10)
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := &safeBuffer{}
			unsub, err := s.Subscribe(buf)
			if err == nil {
				mu.Lock()
				unsubFns[i] = unsub
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	for _, unsub := range unsubFns {
		if unsub != nil {
			unsub()
		}
	}
}

func TestConcurrent_MultipleWriters_NoRace(t *testing.T) {
	s := newStreamer(10)
	buf, unsub := subscribeBuffer(t, s)
	defer unsub()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Write([]byte("x")) //nolint:errcheck
		}()
	}
	wg.Wait()

	waitFor(t, time.Second, func() bool {
		return buf.Len() == 50
	})
}

// =============================================================================
// Test helpers
// =============================================================================

// safeBuffer is a thread-safe bytes.Buffer.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *safeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// blockingWriter blocks on Write until its block channel is closed.
// Used to simulate a slow observer.
type blockingWriter struct {
	block chan struct{}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	<-b.block
	return len(p), nil
}

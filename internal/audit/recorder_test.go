package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

func newTestRecorder(t *testing.T) (*Recorder, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := NewRecorder(dir, "test-session", 220, 50)
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	return r, r.Path()
}

// readCastFile parses a .cast file and returns the header and all events.
func readCastFile(t *testing.T, path string) (header, []event) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var h header
	var events []event

	scanner := bufio.NewScanner(f)

	// First line is the header.
	require.True(t, scanner.Scan(), "cast file should have at least one line (header)")
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &h))

	// Remaining lines are events.
	for scanner.Scan() {
		var raw [3]interface{}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &raw))
		events = append(events, event{raw[0], raw[1], raw[2]})
	}
	require.NoError(t, scanner.Err())
	return h, events
}

// =============================================================================
// NewRecorder
// =============================================================================

func TestNewRecorder_CreatesFile(t *testing.T) {
	_, path := newTestRecorder(t)
	_, err := os.Stat(path)
	assert.NoError(t, err, "cast file should exist after NewRecorder")
}

func TestNewRecorder_FileNameMatchesSessionID(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRecorder(dir, "my-session-id", 80, 24)
	require.NoError(t, err)
	defer r.Close()
	assert.Equal(t, filepath.Join(dir, "my-session-id.cast"), r.Path())
}

func TestNewRecorder_CreatesStorageDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	r, err := NewRecorder(dir, "session", 80, 24)
	require.NoError(t, err)
	defer r.Close()
	_, err = os.Stat(dir)
	assert.NoError(t, err, "storage dir should be created automatically")
}

func TestNewRecorder_WritesValidHeader(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRecorder(dir, "session-abc", 120, 30)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	h, _ := readCastFile(t, r.Path())
	assert.Equal(t, 2, h.Version)
	assert.Equal(t, 120, h.Width)
	assert.Equal(t, 30, h.Height)
	assert.Equal(t, "session-abc", h.Title)
	assert.NotZero(t, h.Timestamp)
	assert.Equal(t, "xterm-256color", h.Env["TERM"])
}

// =============================================================================
// Record / Write
// =============================================================================

func TestRecord_WritesOutputEvent(t *testing.T) {
	r, path := newTestRecorder(t)
	require.NoError(t, r.Record([]byte("hello")))
	require.NoError(t, r.Close())

	_, events := readCastFile(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, "o", events[0][1])
	assert.Equal(t, "hello", events[0][2])
}

func TestRecord_TimestampIsPositive(t *testing.T) {
	r, path := newTestRecorder(t)
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, r.Record([]byte("data")))
	require.NoError(t, r.Close())

	_, events := readCastFile(t, path)
	require.Len(t, events, 1)
	ts, ok := events[0][0].(float64)
	require.True(t, ok)
	assert.Greater(t, ts, 0.0)
}

func TestRecord_MultipleEventsInOrder(t *testing.T) {
	r, path := newTestRecorder(t)
	require.NoError(t, r.Record([]byte("first")))
	require.NoError(t, r.Record([]byte("second")))
	require.NoError(t, r.Record([]byte("third")))
	require.NoError(t, r.Close())

	_, events := readCastFile(t, path)
	require.Len(t, events, 3)
	assert.Equal(t, "first", events[0][2])
	assert.Equal(t, "second", events[1][2])
	assert.Equal(t, "third", events[2][2])
}

func TestRecord_EmptyDataSkipped(t *testing.T) {
	r, path := newTestRecorder(t)
	require.NoError(t, r.Record([]byte{}))
	require.NoError(t, r.Close())

	_, events := readCastFile(t, path)
	assert.Empty(t, events, "empty record should not produce an event")
}

func TestWrite_ImplementsIOWriter(t *testing.T) {
	r, path := newTestRecorder(t)
	n, err := r.Write([]byte("via Write"))
	require.NoError(t, err)
	assert.Equal(t, 9, n)
	require.NoError(t, r.Close())

	_, events := readCastFile(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, "via Write", events[0][2])
}

// =============================================================================
// Close
// =============================================================================

func TestClose_IdempotentDoubleClose(t *testing.T) {
	r, _ := newTestRecorder(t)
	require.NoError(t, r.Close())
	assert.NoError(t, r.Close(), "second Close should be a no-op")
}

func TestRecord_AfterClose_ReturnsError(t *testing.T) {
	r, _ := newTestRecorder(t)
	require.NoError(t, r.Close())
	err := r.Record([]byte("after close"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recorder already closed")
}

// =============================================================================
// Concurrency
// =============================================================================

func TestRecord_ConcurrentWrites_NoRace(t *testing.T) {
	r, _ := newTestRecorder(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Record([]byte("concurrent data")) //nolint:errcheck
		}()
	}
	wg.Wait()
	assert.NoError(t, r.Close())
}

// =============================================================================
// NopRecorder
// =============================================================================

func TestNopRecorder_WriteAlwaysSucceeds(t *testing.T) {
	n := &NopRecorder{}
	written, err := n.Write([]byte("anything"))
	assert.NoError(t, err)
	assert.Equal(t, 8, written)
}

func TestNopRecorder_RecordAlwaysSucceeds(t *testing.T) {
	n := &NopRecorder{}
	assert.NoError(t, n.Record([]byte("anything")))
}

func TestNopRecorder_CloseAlwaysSucceeds(t *testing.T) {
	n := &NopRecorder{}
	assert.NoError(t, n.Close())
}

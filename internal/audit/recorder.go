package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RecorderIface is the common interface for Recorder and NopRecorder.
// Bridge and server code depend on this interface — never on the concrete type.
type RecorderIface interface {
	io.Writer
	Record(data []byte) error
	Close() error
}

// header is the asciinema v2 .cast file header (first line, JSON).
type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// event is a single asciinema v2 event: [time, type, data]
type event [3]interface{}

// Recorder writes a session to an asciinema v2 .cast file.
// It implements io.WriteCloser — Write records stdout frames.
// Safe for concurrent use.
type Recorder struct {
	mu        sync.Mutex
	f         *os.File
	enc       *json.Encoder
	startTime time.Time
	closed    bool
}

// NopRecorder discards all data — use when recording is disabled
// so bridge.Run() needs no nil checks.
type NopRecorder struct{}

func (n *NopRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (n *NopRecorder) Record(data []byte) error    { return nil }
func (n *NopRecorder) Close() error                { return nil }

// NewRecorder creates a Recorder writing to storagePath/<sessionID>.cast.
// The directory is created if it does not exist.
func NewRecorder(storagePath, sessionID string, width, height int) (*Recorder, error) {
	if storagePath == "" {
		return nil, fmt.Errorf("audit: storage path is empty")
	}

	if err := os.MkdirAll(storagePath, 0o755); err != nil {
		return nil, fmt.Errorf("audit: create storage dir: %w", err)
	}

	path := filepath.Join(storagePath, sessionID+".cast")
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("audit: create cast file %s: %w", path, err)
	}

	r := &Recorder{
		f:         f,
		enc:       json.NewEncoder(f),
		startTime: time.Now(),
	}

	h := header{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: r.startTime.Unix(),
		Title:     sessionID,
		Env:       map[string]string{"TERM": "xterm-256color"},
	}
	if err := r.enc.Encode(h); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: write cast header: %w", err)
	}

	return r, nil
}

// Write records p as a stdout event. Implements io.Writer for use
// with io.MultiWriter in bridge.Run().
func (r *Recorder) Write(p []byte) (int, error) {
	if err := r.Record(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Record writes data as a stdout ("o") event with a relative timestamp.
func (r *Recorder) Record(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("audit: recorder already closed")
	}
	elapsed := time.Since(r.startTime).Seconds()
	return r.enc.Encode(event{elapsed, "o", string(data)})
}

// Close flushes and closes the underlying file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.f.Close()
}

// Path returns the absolute path to the .cast file.
func (r *Recorder) Path() string {
	return r.f.Name()
}

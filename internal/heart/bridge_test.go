package heart

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

type outputBuffer interface {
	io.Writer
	String() string
	Len() int
	Bytes() []byte
}

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

// pipe creates a pair of connected buffers simulating a bidirectional stream.
// readWriter.Read() reads from src, readWriter.Write() writes to dst.
type pipeReadWriter struct {
	src *bytes.Buffer // data to be read by Read()
	dst io.Writer     // data written by Write()
}

func (p *pipeReadWriter) Read(b []byte) (int, error) {
	return p.src.Read(b)
}

func (p *pipeReadWriter) Write(b []byte) (int, error) {
	return p.dst.Write(b)
}

// writeCloser wraps bytes.Buffer in io.WriteCloser.
// closed tracks whether Close() has been called.
type writeCloser struct {
	buf    *bytes.Buffer
	closed bool
	mu     sync.Mutex
}

func newWriteCloser() *writeCloser {
	return &writeCloser{buf: &bytes.Buffer{}}
}

func (w *writeCloser) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(b)
}

func (w *writeCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *writeCloser) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Bytes()
}

func (w *writeCloser) WasClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

// newBridgeFixture creates a ready Bridge with controlled buffers.
//
//	clientInput  — data the client "sends" (read by bridge as stdin)
//	targetStdout — data the server sends to stdout
//	targetStderr — data the server sends to stderr
//
// Returns bridge, targetStdin (where client input goes),
// and clientOutput (where stdout+stderr goes if client is not ssh.Channel).
func newBridgeFixture(clientInput, targetStdoutData, targetStderrData string) (
	b *Bridge,
	targetStdin *writeCloser,
	clientOutput outputBuffer,
) {
	clientOutput = &safeBuffer{}

	// client: Read() returns clientInput, Write() goes to clientOutput
	client := &pipeReadWriter{
		src: bytes.NewBufferString(clientInput),
		dst: clientOutput,
	}

	targetStdin = newWriteCloser()
	stdout := strings.NewReader(targetStdoutData)
	stderr := strings.NewReader(targetStderrData)

	b = NewBridge(client, targetStdin, stdout, stderr)
	return b, targetStdin, clientOutput
}

// =============================================================================
// NewBridge
// =============================================================================

func TestNewBridge_StoresAllFields(t *testing.T) {
	client := &pipeReadWriter{src: &bytes.Buffer{}, dst: &bytes.Buffer{}}
	stdin := newWriteCloser()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	b := NewBridge(client, stdin, stdout, stderr)

	require.NotNil(t, b)
	assert.Equal(t, client, b.client)
	assert.Equal(t, stdin, b.targetStdin)
	assert.Equal(t, stdout, b.targetStdout)
	assert.Equal(t, stderr, b.targetStderr)
}

// =============================================================================
// Run — stdout data flow
// =============================================================================

func TestRun_StdoutFlowsToClient(t *testing.T) {
	b, _, clientOutput := newBridgeFixture("", "hello from server", "")

	b.Run()

	assert.Equal(t, "hello from server", clientOutput.String())
}

func TestRun_StdoutEmptyDoesNotBlock(t *testing.T) {
	b, _, clientOutput := newBridgeFixture("", "", "")

	done := make(chan struct{})
	go func() {
		b.Run()
		close(done)
	}()

	select {
	case <-done:
		// correct — Run has finished
	case <-time.After(time.Second):
		t.Fatal("Run blocked on empty stdout")
	}

	assert.Empty(t, clientOutput.String())
}

func TestRun_StdoutLargePayload(t *testing.T) {
	// 1MB of data — verifies bridge handles large payloads without issues
	payload := strings.Repeat("x", 1024*1024)
	b, _, clientOutput := newBridgeFixture("", payload, "")

	b.Run()

	assert.Equal(t, len(payload), clientOutput.Len())
}

func TestRun_StdoutMultilinePreservesContent(t *testing.T) {
	data := "line1\nline2\nline3\n"
	b, _, clientOutput := newBridgeFixture("", data, "")

	b.Run()

	assert.Equal(t, data, clientOutput.String())
}

// =============================================================================
// Run — stderr data flow (fallback to stdout when not ssh.Channel)
// =============================================================================

func TestRun_StderrFallsBackToClientWhenNotSSHChannel(t *testing.T) {
	// client does not implement ssh.Channel — stderr goes to the same buffer as stdout
	b, _, clientOutput := newBridgeFixture("", "", "error from server")

	b.Run()

	assert.Equal(t, "error from server", clientOutput.String())
}

func TestRun_StdoutAndStderrBothReachClient(t *testing.T) {
	// Both streams go to clientOutput when client is not ssh.Channel
	b, _, clientOutput := newBridgeFixture("", "stdout-data", "stderr-data")

	b.Run()

	output := clientOutput.String()
	assert.Contains(t, output, "stdout-data")
	assert.Contains(t, output, "stderr-data")
}

// =============================================================================
// Run — stdin data flow (client → server)
// =============================================================================

func TestRun_StdinFlowsToTarget(t *testing.T) {
	b, targetStdin, _ := newBridgeFixture("ls -la\n", "", "")

	b.Run()

	assert.Equal(t, "ls -la\n", string(targetStdin.Bytes()))
}

func TestRun_StdinEmptyDoesNotBlock(t *testing.T) {
	b, targetStdin, _ := newBridgeFixture("", "", "")

	done := make(chan struct{})
	go func() {
		b.Run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run blocked on empty stdin")
	}

	assert.Empty(t, targetStdin.Bytes())
}

func TestRun_StdinLargePayload(t *testing.T) {
	payload := strings.Repeat("cmd\n", 10000)
	b, targetStdin, _ := newBridgeFixture(payload, "", "")

	b.Run()

	assert.Equal(t, payload, string(targetStdin.Bytes()))
}

// =============================================================================
// Run — targetStdin close
// =============================================================================

func TestRun_ClosesTargetStdinAfterEOF(t *testing.T) {
	// After client input is exhausted the bridge must close targetStdin
	// so the target server receives EOF and can end the session.
	b, targetStdin, _ := newBridgeFixture("some input", "", "")

	b.Run()

	assert.True(t, targetStdin.WasClosed(),
		"targetStdin.Close() should be called after copying is done")
}

func TestRun_ClosesTargetStdinEvenWhenEmpty(t *testing.T) {
	b, targetStdin, _ := newBridgeFixture("", "", "")

	b.Run()

	assert.True(t, targetStdin.WasClosed(),
		"targetStdin.Close() should be called even when stdin is empty")
}

// =============================================================================
// Run — concurrent flow of all streams
// =============================================================================

func TestRun_AllStreamsFlowConcurrently(t *testing.T) {
	// All three directions work concurrently — we verify that data
	// from all streams reaches the correct destinations.
	b, targetStdin, clientOutput := newBridgeFixture(
		"client-input",
		"server-stdout",
		"server-stderr",
	)

	b.Run()

	assert.Equal(t, "client-input", string(targetStdin.Bytes()),
		"client stdin should reach targetStdin")

	output := clientOutput.String()
	assert.Contains(t, output, "server-stdout",
		"server stdout should reach the client")
	assert.Contains(t, output, "server-stderr",
		"server stderr should reach the client")

	assert.True(t, targetStdin.WasClosed(),
		"targetStdin should be closed after completion")
}

// =============================================================================
// Run — blocking and completion
// =============================================================================

func TestRun_BlocksUntilAllStreamsDone(t *testing.T) {
	// Run() must block until all three goroutines finish.
	// We verify by checking that all data is available after Run().
	b, targetStdin, clientOutput := newBridgeFixture(
		"input",
		"output",
		"errors",
	)

	b.Run() // must block and return only when everything is copied

	// After Run() all data must already be in the buffers — no race condition.
	assert.NotEmpty(t, targetStdin.Bytes())
	assert.NotEmpty(t, clientOutput.Bytes())
}

func TestRun_CanBeCalledOnceOnly(t *testing.T) {
	// Run() is one-shot — a second call on the same Bridge
	// should not panic (streams will be exhausted, returns immediately).
	b, _, _ := newBridgeFixture("data", "output", "")

	b.Run()

	// Second Run — streams exhausted, should return without panicking.
	assert.NotPanics(t, func() { b.Run() })
}

// =============================================================================
// Run — reader returning an error
// =============================================================================

// errorReader implements io.Reader that always returns an error.
// Simulates a sudden SSH connection drop.
type errorReader struct{ err error }

func (e *errorReader) Read([]byte) (int, error) { return 0, e.err }

func TestRun_HandlesErrorOnStdout(t *testing.T) {
	// io.Copy ends when reader returns an error — bridge should not panic.
	client := &pipeReadWriter{src: &bytes.Buffer{}, dst: &bytes.Buffer{}}
	stdin := newWriteCloser()
	stdout := &errorReader{err: io.ErrUnexpectedEOF}
	stderr := &bytes.Buffer{}

	b := NewBridge(client, stdin, stdout, stderr)

	assert.NotPanics(t, func() { b.Run() })
}

func TestRun_HandlesErrorOnStderr(t *testing.T) {
	client := &pipeReadWriter{src: &bytes.Buffer{}, dst: &bytes.Buffer{}}
	stdin := newWriteCloser()
	stdout := &bytes.Buffer{}
	stderr := &errorReader{err: io.ErrClosedPipe}

	b := NewBridge(client, stdin, stdout, stderr)

	assert.NotPanics(t, func() { b.Run() })
}

// =============================================================================
// Run — ssh.Channel type assertion for stderr
// =============================================================================

// mockSSHChannel implements a minimal ssh.Channel for testing
// the stderr path when client is ssh.Channel.
type mockSSHChannel struct {
	io.ReadWriter
	stderrBuf *bytes.Buffer
}

func (m *mockSSHChannel) Stderr() io.ReadWriter { return m.stderrBuf }
func (m *mockSSHChannel) CloseWrite() error     { return nil }
func (m *mockSSHChannel) Close() error          { return nil }
func (m *mockSSHChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
	return false, nil
}

func TestRun_StderrGoesToChannelStderrWhenSSHChannel(t *testing.T) {
	// When client implements ssh.Channel — stderr goes to ch.Stderr(),
	// not to the main client stream.
	stderrBuf := &bytes.Buffer{}
	clientBuf := &bytes.Buffer{}

	ch := &mockSSHChannel{
		ReadWriter: &pipeReadWriter{
			src: &bytes.Buffer{}, // empty client input
			dst: clientBuf,
		},
		stderrBuf: stderrBuf,
	}

	stdin := newWriteCloser()
	stdout := strings.NewReader("stdout-data")
	stderr := strings.NewReader("stderr-data")

	b := NewBridge(ch, stdin, stdout, stderr)
	b.Run()

	// stderr goes to ch.Stderr() — not to clientBuf
	assert.Equal(t, "stderr-data", stderrBuf.String(),
		"stderr should go to ch.Stderr()")
	assert.NotContains(t, clientBuf.String(), "stderr-data",
		"stderr should not go to the main client stream")

	// stdout still goes to clientBuf
	assert.Equal(t, "stdout-data", clientBuf.String(),
		"stdout should go to the main client stream")
}

package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"truthsayer/internal/config"
	"truthsayer/internal/proxy"
)

// =============================================================================
// Helpers
// =============================================================================

func startBastionWithRecorder(t *testing.T, targetAddr, targetUser, targetPass, storagePath string) string {
	t.Helper()

	auth := proxy.AuthConfig{
		Users: map[string]string{"testuser": "testpass"},
	}
	target := proxy.TargetConfig{
		Addr:     targetAddr,
		User:     targetUser,
		Password: targetPass,
	}
	audit := config.Audit{
		StoragePath: storagePath,
		LogLevel:    "info",
	}

	srv, err := proxy.NewSSHServer(
		"127.0.0.1:0",
		generateSigner(t),
		auth,
		target,
		proxy.LimitsConfig{},
		config.Security{},
		audit,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.Start(ctx) //nolint:errcheck

	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("bastion did not become ready within 3s")
	}

	return srv.Addr()
}

// castHeader mirrors the asciinema v2 header for JSON parsing in tests.
type castHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// castEvent is a single asciinema v2 event line: [time, type, data].
type castEvent struct {
	Time float64
	Type string
	Data string
}

// readCastFiles returns all .cast files found in dir.
func readCastFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "*.cast"))
	require.NoError(t, err)
	return entries
}

// parseCastFile parses a .cast file into a header and list of events.
func parseCastFile(t *testing.T, path string) (castHeader, []castEvent) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var h castHeader
	var events []castEvent

	scanner := bufio.NewScanner(f)

	require.True(t, scanner.Scan(), "cast file must have a header line")
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &h))

	for scanner.Scan() {
		var raw [3]interface{}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &raw))
		ts, _ := raw[0].(float64)
		typ, _ := raw[1].(string)
		data, _ := raw[2].(string)
		events = append(events, castEvent{Time: ts, Type: typ, Data: data})
	}
	require.NoError(t, scanner.Err())
	return h, events
}

// =============================================================================
// E2E Recorder Tests
// =============================================================================

func TestE2ERecorder_CastFileCreatedAfterSession(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo hello")

	// Give recorder time to flush and close.
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	assert.NotEmpty(t, files, "at least one .cast file should exist after session")
}

func TestE2ERecorder_CastFileHasValidHeader(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo hello")
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	require.NotEmpty(t, files)

	h, _ := parseCastFile(t, files[0])
	assert.Equal(t, 2, h.Version, "asciinema v2 format required")
	assert.NotZero(t, h.Width)
	assert.NotZero(t, h.Height)
	assert.NotZero(t, h.Timestamp)
}

func TestE2ERecorder_CastFileContainsOutputEvents(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo hello")
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	require.NotEmpty(t, files)

	_, events := parseCastFile(t, files[0])
	require.NotEmpty(t, events, "cast file should contain at least one event")

	// All events must be output type.
	for _, e := range events {
		assert.Equal(t, "o", e.Type, "all recorded events should be stdout events")
	}
}

func TestE2ERecorder_CastFileContainsCommandOutput(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo truthsayer")
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	require.NotEmpty(t, files)

	_, events := parseCastFile(t, files[0])

	// Concatenate all event data and check for expected output.
	var combined string
	for _, e := range events {
		combined += e.Data
	}
	assert.Contains(t, combined, "truthsayer", "command output should appear in recording")
}

func TestE2ERecorder_MultipleSessionsProduceMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo first")
	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo second")
	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo third")
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	assert.Len(t, files, 3, "each session should produce a separate .cast file")
}

func TestE2ERecorder_EventTimestampsAreIncreasing(t *testing.T) {
	dir := t.TempDir()
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", dir)

	execOverBastion(t, bastionAddr, "testuser", "testpass", "echo hello")
	time.Sleep(100 * time.Millisecond)

	files := readCastFiles(t, dir)
	require.NotEmpty(t, files)

	_, events := parseCastFile(t, files[0])
	for i := 1; i < len(events); i++ {
		assert.GreaterOrEqual(t, events[i].Time, events[i-1].Time,
			"event timestamps must be non-decreasing")
	}
}

func TestE2ERecorder_NoRecordingWhenStoragePathEmpty(t *testing.T) {
	// Empty storage path — recorder should fail gracefully and session continues.
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithRecorder(t, targetAddr, "targetuser", "targetpass", "")

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	require.NoError(t, err)
	defer client.Close()

	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()

	out, err := session.Output("echo still works")
	require.NoError(t, err, "session should work even when recorder fails")
	assert.Equal(t, "still works\n", string(out))
}

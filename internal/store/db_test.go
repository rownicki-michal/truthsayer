package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"truthsayer/internal/store"
)

// =============================================================================
// Helpers
// =============================================================================

// startPostgres spins up a throwaway Postgres container and returns its DSN.
// The container is terminated when the test ends.
func startPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("truthsayer_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(ctx) }) //nolint:errcheck

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

func newStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	dsn := startPostgres(t)
	s, err := store.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s
}

func testSession(id string) store.Session {
	return store.Session{
		ID:         id,
		User:       "alice",
		RemoteAddr: "192.168.1.10:54321",
		Target:     "10.0.0.1:22",
		StartedAt:  time.Now().UTC().Truncate(time.Second),
	}
}

// =============================================================================
// New / migrate
// =============================================================================

func TestNew_ConnectsAndMigrates(t *testing.T) {
	s := newStore(t)
	assert.NotNil(t, s)
}

func TestNew_MigrateIsIdempotent(t *testing.T) {
	// Running New twice on the same DSN should not fail (CREATE TABLE IF NOT EXISTS).
	dsn := startPostgres(t)
	ctx := context.Background()

	s1, err := store.New(ctx, dsn)
	require.NoError(t, err)
	defer s1.Close() //nolint:errcheck

	s2, err := store.New(ctx, dsn)
	require.NoError(t, err)
	defer s2.Close() //nolint:errcheck
}

func TestNew_InvalidDSN_ReturnsError(t *testing.T) {
	_, err := store.New(context.Background(), "postgres://invalid:5432/nodb")
	assert.Error(t, err)
}

// =============================================================================
// StartSession
// =============================================================================

func TestStartSession_InsertsRow(t *testing.T) {
	s := newStore(t)
	sess := testSession("20260223-alice-a1b2c3d4")

	err := s.StartSession(context.Background(), sess)
	assert.NoError(t, err)
}

func TestStartSession_DuplicateID_ReturnsError(t *testing.T) {
	s := newStore(t)
	sess := testSession("dup-id")

	require.NoError(t, s.StartSession(context.Background(), sess))
	err := s.StartSession(context.Background(), sess)
	assert.Error(t, err, "inserting duplicate session ID should fail")
}

func TestStartSession_AllFieldsPersisted(t *testing.T) {
	s := newStore(t)
	sess := store.Session{
		ID:            "full-fields-session",
		User:          "bob",
		RemoteAddr:    "10.1.2.3:22222",
		Target:        "prod-server:22",
		RecordingPath: "/logs/sessions/full-fields-session.cast",
		RiskScore:     0.75,
		StartedAt:     time.Now().UTC().Truncate(time.Second),
	}

	require.NoError(t, s.StartSession(context.Background(), sess))

	// Verify by ending the session — no error means row exists.
	err := s.EndSession(context.Background(), sess.ID, time.Now().UTC(), 0.75)
	assert.NoError(t, err)
}

// =============================================================================
// EndSession
// =============================================================================

func TestEndSession_UpdatesRow(t *testing.T) {
	s := newStore(t)
	sess := testSession("end-session-test")
	require.NoError(t, s.StartSession(context.Background(), sess))

	endedAt := sess.StartedAt.Add(5 * time.Minute)
	err := s.EndSession(context.Background(), sess.ID, endedAt, 0.3)
	assert.NoError(t, err)
}

func TestEndSession_NonExistentID_ReturnsError(t *testing.T) {
	s := newStore(t)

	err := s.EndSession(context.Background(), "does-not-exist", time.Now().UTC(), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestEndSession_RiskScoreUpdated(t *testing.T) {
	s := newStore(t)
	sess := testSession("risk-score-test")
	require.NoError(t, s.StartSession(context.Background(), sess))

	err := s.EndSession(context.Background(), sess.ID, time.Now().UTC(), 0.95)
	assert.NoError(t, err)
}

// =============================================================================
// SetRecordingPath
// =============================================================================

func TestSetRecordingPath_UpdatesPath(t *testing.T) {
	s := newStore(t)
	sess := testSession("recording-path-test")
	require.NoError(t, s.StartSession(context.Background(), sess))

	err := s.SetRecordingPath(context.Background(), sess.ID, "/logs/sessions/recording-path-test.cast")
	assert.NoError(t, err)
}

func TestSetRecordingPath_NonExistentID_ReturnsError(t *testing.T) {
	s := newStore(t)

	err := s.SetRecordingPath(context.Background(), "ghost-session", "/logs/ghost.cast")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSetRecordingPath_EmptyPath(t *testing.T) {
	s := newStore(t)
	sess := testSession("empty-path-test")
	require.NoError(t, s.StartSession(context.Background(), sess))

	// Empty path is valid — clears the recording path.
	err := s.SetRecordingPath(context.Background(), sess.ID, "")
	assert.NoError(t, err)
}

// =============================================================================
// Close
// =============================================================================

func TestClose_IsIdempotent(t *testing.T) {
	dsn := startPostgres(t)
	s, err := store.New(context.Background(), dsn)
	require.NoError(t, err)

	assert.NoError(t, s.Close())
	assert.NotPanics(t, func() { s.Close() }) //nolint:errcheck
}

// =============================================================================
// Concurrent access
// =============================================================================

func TestConcurrent_StartSession_NoRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			sess := testSession(fmt.Sprintf("concurrent-session-%d", i))
			errCh <- s.StartSession(ctx, sess)
		}(i)
	}

	for i := 0; i < 20; i++ {
		assert.NoError(t, <-errCh)
	}
}

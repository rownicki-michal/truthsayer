package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Session holds metadata for a single bastion session.
type Session struct {
	ID            string
	User          string
	RemoteAddr    string
	Target        string
	RecordingPath string
	RiskScore     float64
	StartedAt     time.Time
	EndedAt       *time.Time
	DurationSec   *float64
}

// SessionStore persists session metadata to a backing store.
// Implementations must be safe for concurrent use.
type SessionStore interface {
	StartSession(ctx context.Context, s Session) error
	EndSession(ctx context.Context, id string, endedAt time.Time, riskScore float64) error
	SetRecordingPath(ctx context.Context, id string, path string) error
	Close() error
}

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
	id             TEXT        PRIMARY KEY,
	user_name      TEXT        NOT NULL,
	remote_addr    TEXT        NOT NULL,
	target         TEXT        NOT NULL,
	recording_path TEXT        NOT NULL DEFAULT '',
	risk_score     FLOAT8      NOT NULL DEFAULT 0,
	started_at     TIMESTAMPTZ NOT NULL,
	ended_at       TIMESTAMPTZ,
	duration_sec   FLOAT8
);`

// PostgresStore implements SessionStore using a pgx connection pool.
// Safe for concurrent use.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// New opens a pgx connection pool to dsn and runs the schema migration.
// dsn format: "postgres://user:pass@host:port/dbname"
func New(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return s, nil
}

// StartSession inserts a new session row.
func (s *PostgresStore) StartSession(ctx context.Context, sess Session) error {
	const q = `
		INSERT INTO sessions (id, user_name, remote_addr, target, recording_path, risk_score, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.pool.Exec(ctx, q,
		sess.ID,
		sess.User,
		sess.RemoteAddr,
		sess.Target,
		sess.RecordingPath,
		sess.RiskScore,
		sess.StartedAt,
	)
	if err != nil {
		return fmt.Errorf("store: start session %s: %w", sess.ID, err)
	}
	return nil
}

// EndSession updates ended_at, duration_sec and risk_score for the session.
func (s *PostgresStore) EndSession(ctx context.Context, id string, endedAt time.Time, riskScore float64) error {
	const q = `
		UPDATE sessions
		SET ended_at     = $2,
		    duration_sec = EXTRACT(EPOCH FROM ($2 - started_at)),
		    risk_score   = $3
		WHERE id = $1`

	tag, err := s.pool.Exec(ctx, q, id, endedAt, riskScore)
	if err != nil {
		return fmt.Errorf("store: end session %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: end session %s: not found", id)
	}
	return nil
}

// SetRecordingPath stores the .cast file path for the session.
func (s *PostgresStore) SetRecordingPath(ctx context.Context, id string, path string) error {
	const q = `UPDATE sessions SET recording_path = $2 WHERE id = $1`

	tag, err := s.pool.Exec(ctx, q, id, path)
	if err != nil {
		return fmt.Errorf("store: set recording path %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: set recording path %s: not found", id)
	}
	return nil
}

// Close shuts down the connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// migrate creates the sessions table if it does not exist.
func (s *PostgresStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

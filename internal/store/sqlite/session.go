// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sigil-dev/sigil/internal/store"
)

// Compile-time interface check.
var _ store.SessionStore = (*SessionStore)(nil)

// SessionStore implements store.SessionStore backed by SQLite.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore opens (or creates) a SQLite database at dbPath and
// initialises the sessions and messages tables.
func NewSessionStore(dbPath string) (*SessionStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging sqlite db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating sqlite db: %w", err)
	}

	return &SessionStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS sessions (
	id             TEXT PRIMARY KEY,
	workspace_id   TEXT NOT NULL,
	user_id        TEXT NOT NULL,
	summary        TEXT NOT NULL DEFAULT '',
	last_compaction TEXT NOT NULL DEFAULT '',
	model_override TEXT NOT NULL DEFAULT '',
	status         TEXT NOT NULL DEFAULT 'active',
	created_at     TEXT NOT NULL,
	updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_workspace ON sessions(workspace_id);

CREATE TABLE IF NOT EXISTS messages (
	id          TEXT PRIMARY KEY,
	session_id  TEXT NOT NULL,
	role        TEXT NOT NULL,
	content     TEXT NOT NULL DEFAULT '',
	tool_call_id TEXT NOT NULL DEFAULT '',
	tool_name   TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL,
	metadata    TEXT NOT NULL DEFAULT '{}',
	FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);
`
	_, err := db.Exec(ddl)
	return err
}

// Close closes the underlying database connection.
func (s *SessionStore) Close() error {
	return s.db.Close()
}

func (s *SessionStore) CreateSession(ctx context.Context, session *store.Session) error {
	const q = `INSERT INTO sessions (id, workspace_id, user_id, summary, last_compaction, model_override, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		session.ID,
		session.WorkspaceID,
		session.UserID,
		session.Summary,
		formatTime(session.LastCompaction),
		session.ModelOverride,
		string(session.Status),
		formatTime(session.CreatedAt),
		formatTime(session.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("creating session %s: %w", session.ID, err)
	}
	return nil
}

func (s *SessionStore) GetSession(ctx context.Context, id string) (*store.Session, error) {
	const q = `SELECT id, workspace_id, user_id, summary, last_compaction, model_override, status, created_at, updated_at
FROM sessions WHERE id = ?`

	var sess store.Session
	var lastComp, createdAt, updatedAt string

	err := s.db.QueryRowContext(ctx, q, id).Scan(
		&sess.ID,
		&sess.WorkspaceID,
		&sess.UserID,
		&sess.Summary,
		&lastComp,
		&sess.ModelOverride,
		&sess.Status,
		&createdAt,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("getting session %s: %w", id, err)
	}

	sess.LastCompaction = parseTime(lastComp)
	sess.CreatedAt = parseTime(createdAt)
	sess.UpdatedAt = parseTime(updatedAt)

	return &sess, nil
}

func (s *SessionStore) UpdateSession(ctx context.Context, session *store.Session) error {
	const q = `UPDATE sessions SET workspace_id = ?, user_id = ?, summary = ?, last_compaction = ?,
model_override = ?, status = ?, updated_at = ? WHERE id = ?`

	result, err := s.db.ExecContext(ctx, q,
		session.WorkspaceID,
		session.UserID,
		session.Summary,
		formatTime(session.LastCompaction),
		session.ModelOverride,
		string(session.Status),
		formatTime(time.Now()),
		session.ID,
	)
	if err != nil {
		return fmt.Errorf("updating session %s: %w", session.ID, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected for session %s: %w", session.ID, err)
	}
	if rows == 0 {
		return fmt.Errorf("session %s not found", session.ID)
	}
	return nil
}

func (s *SessionStore) ListSessions(ctx context.Context, workspaceID string, opts store.ListOpts) ([]*store.Session, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	const q = `SELECT id, workspace_id, user_id, summary, last_compaction, model_override, status, created_at, updated_at
FROM sessions WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, q, workspaceID, limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("listing sessions for workspace %s: %w", workspaceID, err)
	}
	defer rows.Close()

	var sessions []*store.Session
	for rows.Next() {
		var sess store.Session
		var lastComp, createdAt, updatedAt string
		if err := rows.Scan(
			&sess.ID,
			&sess.WorkspaceID,
			&sess.UserID,
			&sess.Summary,
			&lastComp,
			&sess.ModelOverride,
			&sess.Status,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning session row: %w", err)
		}
		sess.LastCompaction = parseTime(lastComp)
		sess.CreatedAt = parseTime(createdAt)
		sess.UpdatedAt = parseTime(updatedAt)
		sessions = append(sessions, &sess)
	}

	return sessions, rows.Err()
}

func (s *SessionStore) DeleteSession(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting session %s: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected for session %s: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("session %s not found", id)
	}
	return nil
}

func (s *SessionStore) AppendMessage(ctx context.Context, sessionID string, msg *store.Message) error {
	metadata, err := json.Marshal(msg.Metadata)
	if err != nil {
		return fmt.Errorf("marshalling message metadata: %w", err)
	}

	const q = `INSERT INTO messages (id, session_id, role, content, tool_call_id, tool_name, created_at, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, q,
		msg.ID,
		sessionID,
		string(msg.Role),
		msg.Content,
		msg.ToolCallID,
		msg.ToolName,
		formatTime(msg.CreatedAt),
		string(metadata),
	)
	if err != nil {
		return fmt.Errorf("appending message %s to session %s: %w", msg.ID, sessionID, err)
	}
	return nil
}

func (s *SessionStore) GetActiveWindow(ctx context.Context, sessionID string, limit int) ([]*store.Message, error) {
	// Sub-select the N most recent, then re-order chronologically.
	const q = `SELECT id, session_id, role, content, tool_call_id, tool_name, created_at, metadata
FROM (
	SELECT id, session_id, role, content, tool_call_id, tool_name, created_at, metadata
	FROM messages WHERE session_id = ?
	ORDER BY created_at DESC LIMIT ?
) ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, q, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("getting active window for session %s: %w", sessionID, err)
	}
	defer rows.Close()

	var msgs []*store.Message
	for rows.Next() {
		var msg store.Message
		var createdAt, metaJSON string
		if err := rows.Scan(
			&msg.ID,
			&msg.SessionID,
			&msg.Role,
			&msg.Content,
			&msg.ToolCallID,
			&msg.ToolName,
			&createdAt,
			&metaJSON,
		); err != nil {
			return nil, fmt.Errorf("scanning message row: %w", err)
		}
		msg.CreatedAt = parseTime(createdAt)
		if metaJSON != "" && metaJSON != "{}" {
			if err := json.Unmarshal([]byte(metaJSON), &msg.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshalling message metadata: %w", err)
			}
		}
		msgs = append(msgs, &msg)
	}

	return msgs, rows.Err()
}

// formatTime serialises a time.Time to RFC3339 with millisecond precision.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseTime deserialises a time string stored in the database.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

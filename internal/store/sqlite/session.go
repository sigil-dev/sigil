// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "pinging sqlite db: %w", err)
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "migrating sqlite db: %w", err)
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
	tool_budget_max_calls_per_turn INTEGER NOT NULL DEFAULT 0,
	tool_budget_max_calls_per_session INTEGER NOT NULL DEFAULT 0,
	tool_budget_used INTEGER NOT NULL DEFAULT 0,
	token_budget_per_session_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_per_hour_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_per_day_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_used_session INTEGER NOT NULL DEFAULT 0,
	token_budget_used_hour INTEGER NOT NULL DEFAULT 0,
	token_budget_used_day INTEGER NOT NULL DEFAULT 0,
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
	threat_info TEXT NOT NULL DEFAULT '{}',
	origin      TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL,
	metadata    TEXT NOT NULL DEFAULT '{}',
	FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);
`
	_, err := db.Exec(ddl)
	if err != nil {
		return err
	}

	// Migrate existing databases: add columns if missing.
	// CREATE TABLE IF NOT EXISTS does not add new columns to existing tables.
	if err := addColumnIfMissing(db, "messages", "threat_info", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "messages", "origin", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	return nil
}

// safeIdentRe matches SQL identifiers that are safe to interpolate into DDL.
// All callers MUST pass compile-time string constants for table, column, and
// columnDef — never values derived from user input or runtime data.
var safeIdentRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// safeDefTokenRe matches a single token that is safe inside a column definition.
// It accepts either a plain SQL identifier/keyword (letters, digits, underscores)
// or a single-quoted string literal whose body contains only alphanumerics,
// underscores, braces, brackets, commas, dots, hyphens, and spaces — covering
// DEFAULT values like '{}' while excluding SQL metacharacters such as
// semicolons, dashes-in-comments, and quote sequences.
var safeDefTokenRe = regexp.MustCompile(`^(?:[a-zA-Z_][a-zA-Z0-9_]*|'[-a-zA-Z0-9_{}[\]., ]*')$`)

// addColumnIfMissing checks whether the named column exists in the given table
// via PRAGMA table_info, and issues ALTER TABLE ADD COLUMN if it does not.
//
// IMPORTANT: table, column, and columnDef MUST be compile-time constants.
// They are validated against safeIdentRe before use, but callers must never
// pass values derived from user input or external sources.
func addColumnIfMissing(db *sql.DB, table, column, columnDef string) error {
	if !safeIdentRe.MatchString(table) {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "addColumnIfMissing: unsafe table name %q", table)
	}
	if !safeIdentRe.MatchString(column) {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "addColumnIfMissing: unsafe column name %q", column)
	}
	// columnDef is a compound expression (e.g. "TEXT NOT NULL DEFAULT '{}'").
	// Validate every whitespace-separated token against safeDefTokenRe so that
	// no unsanitized fragment reaches the ALTER TABLE statement. Each token must
	// be either a plain SQL keyword/identifier or a single-quoted string literal
	// with a restricted character set.
	defTokens := strings.Fields(columnDef)
	if len(defTokens) == 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "addColumnIfMissing: empty column definition")
	}
	for _, tok := range defTokens {
		if !safeDefTokenRe.MatchString(tok) {
			return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "addColumnIfMissing: unsafe token %q in column definition %q", tok, columnDef)
		}
	}

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "querying table_info for %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning table_info for %s: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating table_info for %s: %w", table, err)
	}

	slog.Info("adding missing column to table", "table", table, "column", column)
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + columnDef)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "adding column %s to %s: %w", column, table, err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SessionStore) Close() error {
	return s.db.Close()
}

func (s *SessionStore) CreateSession(ctx context.Context, session *store.Session) error {
	const q = `INSERT INTO sessions (id, workspace_id, user_id, summary, last_compaction, model_override, status,
	tool_budget_max_calls_per_turn, tool_budget_max_calls_per_session, tool_budget_used,
	token_budget_per_session_limit, token_budget_per_hour_limit, token_budget_per_day_limit,
	token_budget_used_session, token_budget_used_hour, token_budget_used_day,
	created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		session.ID,
		session.WorkspaceID,
		session.UserID,
		session.Summary,
		formatTime(session.LastCompaction),
		session.ModelOverride,
		string(session.Status),
		session.ToolBudget.MaxCallsPerTurn,
		session.ToolBudget.MaxCallsPerSession,
		session.ToolBudget.Used,
		session.TokenBudget.MaxPerSession,
		session.TokenBudget.MaxPerHour,
		session.TokenBudget.MaxPerDay,
		session.TokenBudget.UsedSession,
		session.TokenBudget.UsedHour,
		session.TokenBudget.UsedDay,
		formatTime(session.CreatedAt),
		formatTime(session.UpdatedAt),
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "creating session %s: %w", session.ID, err)
	}
	return nil
}

func (s *SessionStore) GetSession(ctx context.Context, id string) (*store.Session, error) {
	const q = `SELECT id, workspace_id, user_id, summary, last_compaction, model_override, status,
	tool_budget_max_calls_per_turn, tool_budget_max_calls_per_session, tool_budget_used,
	token_budget_per_session_limit, token_budget_per_hour_limit, token_budget_per_day_limit,
	token_budget_used_session, token_budget_used_hour, token_budget_used_day,
	created_at, updated_at
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
		&sess.ToolBudget.MaxCallsPerTurn,
		&sess.ToolBudget.MaxCallsPerSession,
		&sess.ToolBudget.Used,
		&sess.TokenBudget.MaxPerSession,
		&sess.TokenBudget.MaxPerHour,
		&sess.TokenBudget.MaxPerDay,
		&sess.TokenBudget.UsedSession,
		&sess.TokenBudget.UsedHour,
		&sess.TokenBudget.UsedDay,
		&createdAt,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreEntityNotFound, "session %s: %w", id, sql.ErrNoRows)
	}
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting session %s: %w", id, err)
	}

	sess.LastCompaction, err = ParseTime(lastComp)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s last_compaction: %w", id, err)
	}
	sess.CreatedAt, err = ParseTime(createdAt)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s created_at: %w", id, err)
	}
	sess.UpdatedAt, err = ParseTime(updatedAt)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s updated_at: %w", id, err)
	}

	return &sess, nil
}

func (s *SessionStore) UpdateSession(ctx context.Context, session *store.Session) error {
	const q = `UPDATE sessions SET workspace_id = ?, user_id = ?, summary = ?, last_compaction = ?,
model_override = ?, status = ?,
tool_budget_max_calls_per_turn = ?, tool_budget_max_calls_per_session = ?, tool_budget_used = ?,
token_budget_per_session_limit = ?, token_budget_per_hour_limit = ?, token_budget_per_day_limit = ?,
token_budget_used_session = ?, token_budget_used_hour = ?, token_budget_used_day = ?,
updated_at = ? WHERE id = ?`

	result, err := s.db.ExecContext(ctx, q,
		session.WorkspaceID,
		session.UserID,
		session.Summary,
		formatTime(session.LastCompaction),
		session.ModelOverride,
		string(session.Status),
		session.ToolBudget.MaxCallsPerTurn,
		session.ToolBudget.MaxCallsPerSession,
		session.ToolBudget.Used,
		session.TokenBudget.MaxPerSession,
		session.TokenBudget.MaxPerHour,
		session.TokenBudget.MaxPerDay,
		session.TokenBudget.UsedSession,
		session.TokenBudget.UsedHour,
		session.TokenBudget.UsedDay,
		formatTime(time.Now()),
		session.ID,
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "updating session %s: %w", session.ID, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "checking rows affected for session %s: %w", session.ID, err)
	}
	if rows == 0 {
		return sigilerr.New(sigilerr.CodeStoreEntityNotFound, "session "+session.ID+" not found")
	}
	return nil
}

func (s *SessionStore) ListSessions(ctx context.Context, workspaceID string, opts store.ListOpts) ([]*store.Session, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	const q = `SELECT id, workspace_id, user_id, summary, last_compaction, model_override, status,
	tool_budget_max_calls_per_turn, tool_budget_max_calls_per_session, tool_budget_used,
	token_budget_per_session_limit, token_budget_per_hour_limit, token_budget_per_day_limit,
	token_budget_used_session, token_budget_used_hour, token_budget_used_day,
	created_at, updated_at
FROM sessions WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, q, workspaceID, limit, opts.Offset)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "listing sessions for workspace %s: %w", workspaceID, err)
	}
	defer func() { _ = rows.Close() }()

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
			&sess.ToolBudget.MaxCallsPerTurn,
			&sess.ToolBudget.MaxCallsPerSession,
			&sess.ToolBudget.Used,
			&sess.TokenBudget.MaxPerSession,
			&sess.TokenBudget.MaxPerHour,
			&sess.TokenBudget.MaxPerDay,
			&sess.TokenBudget.UsedSession,
			&sess.TokenBudget.UsedHour,
			&sess.TokenBudget.UsedDay,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning session row: %w", err)
		}
		sess.LastCompaction, err = ParseTime(lastComp)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s last_compaction: %w", sess.ID, err)
		}
		sess.CreatedAt, err = ParseTime(createdAt)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s created_at: %w", sess.ID, err)
		}
		sess.UpdatedAt, err = ParseTime(updatedAt)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing session %s updated_at: %w", sess.ID, err)
		}
		sessions = append(sessions, &sess)
	}

	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating sessions: %w", err)
	}
	return sessions, nil
}

func (s *SessionStore) DeleteSession(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "deleting session %s: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "checking rows affected for session %s: %w", id, err)
	}
	if rows == 0 {
		return sigilerr.New(sigilerr.CodeStoreEntityNotFound, "session "+id+" not found")
	}
	return nil
}

func (s *SessionStore) AppendMessage(ctx context.Context, sessionID string, msg *store.Message) error {
	metadata, err := json.Marshal(msg.Metadata)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling message metadata: %w", err)
	}

	threatInfo := []byte("{}")
	if msg.Threat != nil {
		threatInfo, err = json.Marshal(msg.Threat)
		if err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling threat info: %w", err)
		}
	}

	const q = `INSERT INTO messages (id, session_id, role, content, tool_call_id, tool_name, threat_info, created_at, metadata, origin)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, q,
		msg.ID,
		sessionID,
		string(msg.Role),
		msg.Content,
		msg.ToolCallID,
		msg.ToolName,
		string(threatInfo),
		formatTime(msg.CreatedAt),
		string(metadata),
		msg.Origin,
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "appending message %s to session %s: %w", msg.ID, sessionID, err)
	}
	return nil
}

func (s *SessionStore) GetActiveWindow(ctx context.Context, sessionID string, limit int) ([]*store.Message, error) {
	// Sub-select the N most recent, then re-order chronologically.
	const q = `SELECT id, session_id, role, content, tool_call_id, tool_name, threat_info, created_at, metadata, origin
FROM (
	SELECT id, session_id, role, content, tool_call_id, tool_name, threat_info, created_at, metadata, origin
	FROM messages WHERE session_id = ?
	ORDER BY created_at DESC LIMIT ?
) ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, q, sessionID, limit)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting active window for session %s: %w", sessionID, err)
	}
	defer func() { _ = rows.Close() }()

	var msgs []*store.Message
	for rows.Next() {
		var msg store.Message
		var createdAt, threatJSON, metaJSON string
		if err := rows.Scan(
			&msg.ID,
			&msg.SessionID,
			&msg.Role,
			&msg.Content,
			&msg.ToolCallID,
			&msg.ToolName,
			&threatJSON,
			&createdAt,
			&metaJSON,
			&msg.Origin,
		); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning message row: %w", err)
		}
		msg.CreatedAt, err = ParseTime(createdAt)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing message %s created_at: %w", msg.ID, err)
		}
		if metaJSON != "" && metaJSON != "{}" {
			if err := json.Unmarshal([]byte(metaJSON), &msg.Metadata); err != nil {
				return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "unmarshalling message metadata: %w", err)
			}
		}
		if threatJSON != "" && threatJSON != "{}" {
			var threat store.ThreatInfo
			if err := json.Unmarshal([]byte(threatJSON), &threat); err != nil {
				return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "unmarshalling threat info: %w", err)
			}
			msg.Threat = &threat
		}
		msgs = append(msgs, &msg)
	}

	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating messages: %w", err)
	}
	return msgs, nil
}

// formatTime serialises a time.Time to RFC3339 with nanosecond precision.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ParseTime deserialises a time string stored in the database.
func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing timestamp %q: %w", s, err)
	}
	return t, nil
}

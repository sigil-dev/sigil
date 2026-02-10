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
var _ store.MessageStore = (*MessageStore)(nil)

// MessageStore implements store.MessageStore backed by SQLite with FTS5.
type MessageStore struct {
	db *sql.DB
}

// NewMessageStore opens (or creates) a SQLite database at dbPath and
// initialises the memory_messages table with FTS5 full-text search.
func NewMessageStore(dbPath string) (*MessageStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite db: %w", err)
	}

	if err := migrateMessages(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating message tables: %w", err)
	}

	return &MessageStore{db: db}, nil
}

func migrateMessages(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS memory_messages (
	rowid        INTEGER PRIMARY KEY AUTOINCREMENT,
	id           TEXT UNIQUE NOT NULL,
	workspace_id TEXT NOT NULL,
	session_id   TEXT NOT NULL,
	role         TEXT NOT NULL,
	content      TEXT NOT NULL DEFAULT '',
	tool_call_id TEXT NOT NULL DEFAULT '',
	tool_name    TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	metadata     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_memory_messages_workspace ON memory_messages(workspace_id);
CREATE INDEX IF NOT EXISTS idx_memory_messages_workspace_created ON memory_messages(workspace_id, created_at);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_messages_fts USING fts5(
	content,
	content='memory_messages',
	content_rowid='rowid'
);

-- Triggers to keep FTS index in sync with the main table.
CREATE TRIGGER IF NOT EXISTS memory_messages_ai AFTER INSERT ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

CREATE TRIGGER IF NOT EXISTS memory_messages_ad AFTER DELETE ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(memory_messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;

CREATE TRIGGER IF NOT EXISTS memory_messages_au AFTER UPDATE ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(memory_messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
	INSERT INTO memory_messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;
`
	_, err := db.Exec(ddl)
	return err
}

// Close closes the underlying database connection.
func (m *MessageStore) Close() error {
	return m.db.Close()
}

// Append inserts a message into the store for the given workspace.
func (m *MessageStore) Append(ctx context.Context, workspaceID string, msg *store.Message) error {
	metadata, err := json.Marshal(msg.Metadata)
	if err != nil {
		return fmt.Errorf("marshalling message metadata: %w", err)
	}

	const q = `INSERT INTO memory_messages (id, workspace_id, session_id, role, content, tool_call_id, tool_name, created_at, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = m.db.ExecContext(ctx, q,
		msg.ID,
		workspaceID,
		msg.SessionID,
		string(msg.Role),
		msg.Content,
		msg.ToolCallID,
		msg.ToolName,
		formatTime(msg.CreatedAt),
		string(metadata),
	)
	if err != nil {
		return fmt.Errorf("appending message %s: %w", msg.ID, err)
	}
	return nil
}

// Search performs a full-text search over messages in the workspace.
func (m *MessageStore) Search(ctx context.Context, workspaceID, query string, opts store.SearchOpts) ([]*store.Message, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	const q = `SELECT mm.id, mm.workspace_id, mm.session_id, mm.role, mm.content,
		mm.tool_call_id, mm.tool_name, mm.created_at, mm.metadata
FROM memory_messages mm
JOIN memory_messages_fts fts ON mm.rowid = fts.rowid
WHERE fts.content MATCH ? AND mm.workspace_id = ?
ORDER BY mm.created_at DESC
LIMIT ? OFFSET ?`

	rows, err := m.db.QueryContext(ctx, q, query, workspaceID, limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("searching messages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanMessages(rows)
}

// GetRange returns messages created between from (inclusive) and to (exclusive).
func (m *MessageStore) GetRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*store.Message, error) {
	const q = `SELECT id, workspace_id, session_id, role, content, tool_call_id, tool_name, created_at, metadata
FROM memory_messages
WHERE workspace_id = ? AND created_at >= ? AND created_at < ?
ORDER BY created_at ASC`

	rows, err := m.db.QueryContext(ctx, q, workspaceID, formatTime(from), formatTime(to))
	if err != nil {
		return nil, fmt.Errorf("getting message range: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanMessages(rows)
}

// Count returns the total number of messages in the workspace.
func (m *MessageStore) Count(ctx context.Context, workspaceID string) (int64, error) {
	var count int64
	err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_messages WHERE workspace_id = ?`,
		workspaceID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting messages: %w", err)
	}
	return count, nil
}

// Trim keeps only the keepLast most recent messages per workspace and
// deletes the rest. Returns the number of deleted messages.
func (m *MessageStore) Trim(ctx context.Context, workspaceID string, keepLast int) (int64, error) {
	const q = `DELETE FROM memory_messages
WHERE workspace_id = ? AND rowid NOT IN (
	SELECT rowid FROM memory_messages
	WHERE workspace_id = ?
	ORDER BY created_at DESC
	LIMIT ?
)`

	result, err := m.db.ExecContext(ctx, q, workspaceID, workspaceID, keepLast)
	if err != nil {
		return 0, fmt.Errorf("trimming messages: %w", err)
	}

	return result.RowsAffected()
}

// scanMessages reads message rows into a slice.
func scanMessages(rows *sql.Rows) ([]*store.Message, error) {
	var msgs []*store.Message
	for rows.Next() {
		var msg store.Message
		var wsID, createdAt, metaJSON string

		if err := rows.Scan(
			&msg.ID,
			&wsID,
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

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return msgs, nil
}

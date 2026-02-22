// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Compile-time interface check.
var _ store.SummaryStore = (*SummaryStore)(nil)

// SummaryStore implements store.SummaryStore backed by SQLite.
type SummaryStore struct {
	db     *sql.DB
	ownsDB bool // if true, Close() will close the underlying db connection
}

// NewSummaryStore opens (or creates) a SQLite database at dbPath and
// initialises the summaries table.
func NewSummaryStore(dbPath string) (*SummaryStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "pinging sqlite db: %w", err)
	}

	if err := migrateSummaries(db); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "migrating summary tables: %w", err)
	}

	return &SummaryStore{db: db, ownsDB: true}, nil
}

// NewSummaryStoreWithDB creates a SummaryStore using an existing database connection.
// The caller retains ownership of the connection; Close() becomes a no-op.
func NewSummaryStoreWithDB(db *sql.DB) (*SummaryStore, error) {
	if err := migrateSummaries(db); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "migrating summary tables: %w", err)
	}

	return &SummaryStore{db: db, ownsDB: false}, nil
}

func migrateSummaries(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS summaries (
	id           TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL,
	from_time    TEXT NOT NULL,
	to_time      TEXT NOT NULL,
	content      TEXT NOT NULL DEFAULT '',
	message_ids  TEXT NOT NULL DEFAULT '[]',
	created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_summaries_workspace ON summaries(workspace_id);
CREATE INDEX IF NOT EXISTS idx_summaries_workspace_range ON summaries(workspace_id, from_time, to_time);
CREATE INDEX IF NOT EXISTS idx_summaries_workspace_created ON summaries(workspace_id, created_at);
`
	_, err := db.Exec(ddl)
	return err
}

// Close closes the underlying database connection if this store owns it.
// Stores created with NewSummaryStoreWithDB do not own the connection.
func (s *SummaryStore) Close() error {
	if s.ownsDB {
		return s.db.Close()
	}
	return nil
}

// Store inserts a summary into the store for the given workspace.
func (s *SummaryStore) Store(ctx context.Context, workspaceID string, summary *store.Summary) error {
	msgIDs, err := json.Marshal(summary.MessageIDs)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling message IDs: %w", err)
	}

	const q = `INSERT INTO summaries (id, workspace_id, from_time, to_time, content, message_ids, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, q,
		summary.ID,
		workspaceID,
		formatTime(summary.FromTime),
		formatTime(summary.ToTime),
		summary.Content,
		string(msgIDs),
		formatTime(summary.CreatedAt),
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "storing summary %s: %w", summary.ID, err)
	}
	return nil
}

// GetByRange returns summaries whose time range falls within [from, to].
// A summary is included if its from_time >= from AND to_time <= to.
func (s *SummaryStore) GetByRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*store.Summary, error) {
	const q = `SELECT id, workspace_id, from_time, to_time, content, message_ids, created_at
FROM summaries
WHERE workspace_id = ? AND from_time >= ? AND to_time <= ?
ORDER BY from_time ASC`

	rows, err := s.db.QueryContext(ctx, q, workspaceID, formatTime(from), formatTime(to))
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting summaries by range: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanSummaries(rows)
}

// GetLatest returns the n most recent summaries ordered by created_at descending.
func (s *SummaryStore) GetLatest(ctx context.Context, workspaceID string, n int) ([]*store.Summary, error) {
	const q = `SELECT id, workspace_id, from_time, to_time, content, message_ids, created_at
FROM summaries
WHERE workspace_id = ?
ORDER BY created_at DESC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, workspaceID, n)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting latest summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanSummaries(rows)
}

// scanSummaries reads summary rows into a slice.
func scanSummaries(rows *sql.Rows) ([]*store.Summary, error) {
	var summaries []*store.Summary
	for rows.Next() {
		var sm store.Summary
		var fromTime, toTime, createdAt, msgIDsJSON string

		if err := rows.Scan(
			&sm.ID,
			&sm.WorkspaceID,
			&fromTime,
			&toTime,
			&sm.Content,
			&msgIDsJSON,
			&createdAt,
		); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning summary row: %w", err)
		}

		var err error
		sm.FromTime, err = ParseTime(fromTime)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing summary %s from_time: %w", sm.ID, err)
		}
		sm.ToTime, err = ParseTime(toTime)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing summary %s to_time: %w", sm.ID, err)
		}
		sm.CreatedAt, err = ParseTime(createdAt)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing summary %s created_at: %w", sm.ID, err)
		}

		if msgIDsJSON != "" && msgIDsJSON != "[]" {
			if err := json.Unmarshal([]byte(msgIDsJSON), &sm.MessageIDs); err != nil {
				return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "unmarshalling message IDs: %w", err)
			}
		}

		summaries = append(summaries, &sm)
	}

	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating summaries: %w", err)
	}
	return summaries, nil
}

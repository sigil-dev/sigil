// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	sqlite_vec "github.com/asg017/sqlite-vec-go-bindings/cgo"
	_ "github.com/mattn/go-sqlite3"

	"github.com/sigil-dev/sigil/internal/store"
)

func init() {
	sqlite_vec.Auto()
}

// Compile-time interface check.
var _ store.VectorStore = (*VectorStore)(nil)

// VectorStore implements store.VectorStore backed by SQLite with sqlite-vec.
type VectorStore struct {
	db         *sql.DB
	dimensions int
}

// NewVectorStore opens (or creates) a SQLite database at dbPath and
// initialises the vec0 virtual table and companion metadata table.
func NewVectorStore(dbPath string, dimensions int) (*VectorStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite db: %w", err)
	}

	if err := migrateVector(db, dimensions); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating vector tables: %w", err)
	}

	return &VectorStore{db: db, dimensions: dimensions}, nil
}

func migrateVector(db *sql.DB, dimensions int) error {
	vecDDL := fmt.Sprintf(
		`CREATE VIRTUAL TABLE IF NOT EXISTS vectors USING vec0(id TEXT PRIMARY KEY, embedding float[%d])`,
		dimensions,
	)
	if _, err := db.Exec(vecDDL); err != nil {
		return fmt.Errorf("creating vectors virtual table: %w", err)
	}

	const metaDDL = `
CREATE TABLE IF NOT EXISTS vector_metadata (
	id       TEXT PRIMARY KEY,
	metadata TEXT NOT NULL DEFAULT '{}'
)`
	if _, err := db.Exec(metaDDL); err != nil {
		return fmt.Errorf("creating vector_metadata table: %w", err)
	}

	return nil
}

// Store inserts or replaces a vector and its metadata.
func (v *VectorStore) Store(ctx context.Context, id string, embedding []float32, metadata map[string]any) error {
	blob, err := sqlite_vec.SerializeFloat32(embedding)
	if err != nil {
		return fmt.Errorf("serializing embedding: %w", err)
	}

	metaJSON := []byte("{}")
	if len(metadata) > 0 {
		metaJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("marshalling metadata: %w", err)
		}
	}

	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// vec0 does not support ON CONFLICT; delete first for upsert.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vectors WHERE id = ?`, id); err != nil {
		return fmt.Errorf("deleting existing vector %s: %w", id, err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO vectors(id, embedding) VALUES (?, ?)`, id, blob); err != nil {
		return fmt.Errorf("inserting vector %s: %w", id, err)
	}

	const metaQ = `INSERT INTO vector_metadata(id, metadata) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET metadata = excluded.metadata`
	if _, err := tx.ExecContext(ctx, metaQ, id, string(metaJSON)); err != nil {
		return fmt.Errorf("upserting vector metadata %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing vector store: %w", err)
	}
	return nil
}

// Search performs a k-nearest-neighbor search and returns results with metadata.
// Score represents distance (lower = more similar); 0.0 = exact match.
// Filters are not yet implemented and will return an error if non-empty.
func (v *VectorStore) Search(ctx context.Context, query []float32, k int, filters map[string]any) ([]store.VectorResult, error) {
	if len(filters) > 0 {
		return nil, fmt.Errorf("vector search filters not yet implemented")
	}
	blob, err := sqlite_vec.SerializeFloat32(query)
	if err != nil {
		return nil, fmt.Errorf("serializing query vector: %w", err)
	}

	const q = `SELECT v.id, v.distance, COALESCE(m.metadata, '{}')
FROM vectors v
LEFT JOIN vector_metadata m ON m.id = v.id
WHERE v.embedding MATCH ? AND k = ?
ORDER BY v.distance`

	rows, err := v.db.QueryContext(ctx, q, blob, k)
	if err != nil {
		return nil, fmt.Errorf("searching vectors: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []store.VectorResult
	for rows.Next() {
		var r store.VectorResult
		var metaStr string

		if err := rows.Scan(&r.ID, &r.Score, &metaStr); err != nil {
			return nil, fmt.Errorf("scanning vector result: %w", err)
		}

		if metaStr != "" && metaStr != "{}" {
			if err := json.Unmarshal([]byte(metaStr), &r.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshalling vector metadata: %w", err)
			}
		}

		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vector results: %w", err)
	}

	return results, nil
}

// Delete removes vectors and their metadata by ID.
func (v *VectorStore) Delete(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM vectors WHERE id IN (`+placeholders+`)`, args...); err != nil {
		return fmt.Errorf("deleting vectors: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM vector_metadata WHERE id IN (`+placeholders+`)`, args...); err != nil {
		return fmt.Errorf("deleting vector metadata: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing vector delete: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (v *VectorStore) Close() error {
	return v.db.Close()
}

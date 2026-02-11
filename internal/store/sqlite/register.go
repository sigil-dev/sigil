// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/sigil-dev/sigil/internal/store"
)

func init() {
	store.RegisterBackend("sqlite", newWorkspaceStores, newGatewayStore)
}

func newWorkspaceStores(workspacePath string, vectorDims int) (store.SessionStore, store.MemoryStore, store.VectorStore, error) {
	// Track opened stores for cleanup on partial failure.
	var closers []interface{ Close() error }
	cleanup := func() error {
		var errs []error
		for _, c := range closers {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			joined := errors.Join(errs...)
			slog.Warn("cleanup errors during partial-failure cleanup", "error", joined)
			return joined
		}
		return nil
	}

	ss, err := NewSessionStore(filepath.Join(workspacePath, "sessions.db"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating session store: %w", err)
	}
	closers = append(closers, ss)

	// Open memory.db once and share between MessageStore and SummaryStore
	// to avoid connection waste and WAL contention.
	memoryDB, err := sql.Open("sqlite3", filepath.Join(workspacePath, "memory.db")+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("opening memory db: %w", err), cleanup())
	}
	// Note: memoryDB is not added to closers here; it's closed via msgStore/sumStore Close()

	msgStore, err := NewMessageStoreWithDB(memoryDB)
	if err != nil {
		_ = memoryDB.Close()
		return nil, nil, nil, errors.Join(fmt.Errorf("creating message store: %w", err), cleanup())
	}
	closers = append(closers, msgStore)

	sumStore, err := NewSummaryStoreWithDB(memoryDB)
	if err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("creating summary store: %w", err), cleanup())
	}
	closers = append(closers, sumStore)

	kStore, err := NewKnowledgeStore(filepath.Join(workspacePath, "knowledge.db"))
	if err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("creating knowledge store: %w", err), cleanup())
	}
	closers = append(closers, kStore)

	ms := store.NewCompositeMemoryStore(msgStore, sumStore, kStore)

	vs, err := NewVectorStore(filepath.Join(workspacePath, "vectors.db"), vectorDims)
	if err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("creating vector store: %w", err), cleanup())
	}

	return ss, ms, vs, nil
}

func newGatewayStore(dataPath string) (store.GatewayStore, error) {
	return NewGatewayStore(filepath.Join(dataPath, "gateway.db"))
}

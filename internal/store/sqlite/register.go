// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"fmt"
	"path/filepath"

	"github.com/sigil-dev/sigil/internal/store"
)

func init() {
	store.RegisterBackend("sqlite", newWorkspaceStores, newGatewayStore)
}

func newWorkspaceStores(workspacePath string, vectorDims int) (store.SessionStore, store.MemoryStore, store.VectorStore, error) {
	// Track opened stores for cleanup on partial failure.
	var closers []interface{ Close() error }
	cleanup := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}

	ss, err := NewSessionStore(filepath.Join(workspacePath, "sessions.db"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating session store: %w", err)
	}
	closers = append(closers, ss)

	msgStore, err := NewMessageStore(filepath.Join(workspacePath, "memory.db"))
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("creating message store: %w", err)
	}
	closers = append(closers, msgStore)

	sumStore, err := NewSummaryStore(filepath.Join(workspacePath, "memory.db"))
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("creating summary store: %w", err)
	}
	closers = append(closers, sumStore)

	kStore, err := NewKnowledgeStore(filepath.Join(workspacePath, "knowledge.db"))
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("creating knowledge store: %w", err)
	}
	closers = append(closers, kStore)

	ms := store.NewCompositeMemoryStore(msgStore, sumStore, kStore)

	vs, err := NewVectorStore(filepath.Join(workspacePath, "vectors.db"), vectorDims)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("creating vector store: %w", err)
	}

	return ss, ms, vs, nil
}

func newGatewayStore(dataPath string) (store.GatewayStore, error) {
	return NewGatewayStore(filepath.Join(dataPath, "gateway.db"))
}

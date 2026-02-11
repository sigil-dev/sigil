// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// defaultVectorDimensions is the default embedding dimension (matches OpenAI text-embedding-ada-002).
const defaultVectorDimensions = 1536

// WorkspaceStoreFactory creates workspace-scoped stores given a directory path
// and vector dimensions.
type WorkspaceStoreFactory func(workspacePath string, vectorDims int) (SessionStore, MemoryStore, VectorStore, error)

// GatewayStoreFactory creates the global gateway store given a directory path.
type GatewayStoreFactory func(dataPath string) (GatewayStore, error)

var (
	workspaceFactories = map[string]WorkspaceStoreFactory{}
	gatewayFactories   = map[string]GatewayStoreFactory{}
	factoriesMu        sync.RWMutex
)

// RegisterBackend registers factory functions for a named storage backend.
// Backend packages call this from init(). This function is goroutine-safe.
func RegisterBackend(name string, ws WorkspaceStoreFactory, gw GatewayStoreFactory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	workspaceFactories[name] = ws
	gatewayFactories[name] = gw
}

// resolveBackend returns the effective backend name, defaulting to "sqlite".
func resolveBackend(cfg *StorageConfig) string {
	if cfg.Backend == "" {
		return "sqlite"
	}
	return cfg.Backend
}

// NewWorkspaceStores creates all stores for a workspace.
// The workspacePath directory is used to derive per-database file paths.
func NewWorkspaceStores(cfg *StorageConfig, workspacePath string) (SessionStore, MemoryStore, VectorStore, error) {
	backend := resolveBackend(cfg)

	factoriesMu.RLock()
	factory, ok := workspaceFactories[backend]
	factoriesMu.RUnlock()
	if !ok {
		return nil, nil, nil, fmt.Errorf("unsupported storage backend: %q", backend)
	}

	dims := defaultVectorDimensions
	if cfg.VectorDimensions > 0 {
		dims = cfg.VectorDimensions
	}

	return factory(workspacePath, dims)
}

// NewGatewayStore creates the global gateway store.
func NewGatewayStore(cfg *StorageConfig, dataPath string) (GatewayStore, error) {
	backend := resolveBackend(cfg)

	factoriesMu.RLock()
	factory, ok := gatewayFactories[backend]
	factoriesMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unsupported storage backend: %q", backend)
	}

	return factory(dataPath)
}

// compositeMemoryStore satisfies MemoryStore by composing three sub-stores.
type compositeMemoryStore struct {
	messages  MessageStore
	summaries SummaryStore
	knowledge KnowledgeStore
	closers   []io.Closer // additional resources to close (e.g. shared DB connections)
}

// NewCompositeMemoryStore creates a MemoryStore from individual sub-stores.
// Backend packages use this to avoid duplicating the composition logic.
// Additional closers (e.g. shared database connections) are closed after
// the sub-stores during Close().
func NewCompositeMemoryStore(msgs MessageStore, sums SummaryStore, know KnowledgeStore, closers ...io.Closer) MemoryStore {
	return &compositeMemoryStore{
		messages:  msgs,
		summaries: sums,
		knowledge: know,
		closers:   closers,
	}
}

func (c *compositeMemoryStore) Messages() MessageStore    { return c.messages }
func (c *compositeMemoryStore) Summaries() SummaryStore   { return c.summaries }
func (c *compositeMemoryStore) Knowledge() KnowledgeStore { return c.knowledge }

func (c *compositeMemoryStore) Close() error {
	var errs []error
	if err := c.messages.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.summaries.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.knowledge.Close(); err != nil {
		errs = append(errs, err)
	}
	for _, cl := range c.closers {
		if err := cl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

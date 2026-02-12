// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"

	"github.com/sigil-dev/sigil/internal/store"
)

// ShouldCompact returns true when count >= batchSize, indicating
// that enough messages have accumulated to trigger a compaction pass.
func ShouldCompact(count int64, batchSize int) bool {
	return count >= int64(batchSize)
}

// CompactorConfig holds the dependencies and tuning parameters for a Compactor.
type CompactorConfig struct {
	MemoryStore  store.MemoryStore
	VectorStore  store.VectorStore
	SessionStore store.SessionStore
	BatchSize    int
	WindowSize   int
}

// Compactor manages the memory compaction lifecycle: rolling messages into
// long-term storage and (in Phase 6) summarising and extracting facts.
type Compactor struct {
	cfg CompactorConfig
}

// NewCompactor creates a Compactor with the given configuration.
func NewCompactor(cfg CompactorConfig) *Compactor {
	return &Compactor{cfg: cfg}
}

// RollMessage appends a message to Tier 1 (message store) and stores a
// placeholder embedding in Tier 4 (vector store). Full compaction
// (summarise + extract facts) is deferred to Phase 6.
func (c *Compactor) RollMessage(ctx context.Context, workspaceID, sessionID string, msg *store.Message) error {
	if err := c.cfg.MemoryStore.Messages().Append(ctx, workspaceID, msg); err != nil {
		return err
	}

	return c.cfg.VectorStore.Store(ctx, msg.ID, []float32{0}, map[string]any{
		"workspace_id": workspaceID,
		"session_id":   sessionID,
		"content":      msg.Content,
	})
}

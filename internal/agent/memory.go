// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
)

// MemoryTools provides memory retrieval operations that the agent loop
// can expose as LLM-callable tools.
type MemoryTools struct {
	memoryStore store.MemoryStore
	vectorStore store.VectorStore
}

// NewMemoryTools creates a MemoryTools backed by the given stores.
func NewMemoryTools(ms store.MemoryStore, vs store.VectorStore) *MemoryTools {
	return &MemoryTools{
		memoryStore: ms,
		vectorStore: vs,
	}
}

// Search performs a full-text search over stored messages.
func (mt *MemoryTools) Search(ctx context.Context, workspaceID, query string) ([]*store.Message, error) {
	return mt.memoryStore.Messages().Search(ctx, workspaceID, query, store.SearchOpts{})
}

// Summary retrieves compacted summaries within the given time range.
func (mt *MemoryTools) Summary(ctx context.Context, workspaceID string, from, to time.Time) ([]*store.Summary, error) {
	return mt.memoryStore.Summaries().GetByRange(ctx, workspaceID, from, to)
}

// Recall retrieves known facts about a topic (entity).
func (mt *MemoryTools) Recall(ctx context.Context, workspaceID, topic string) ([]*store.Fact, error) {
	return mt.memoryStore.Knowledge().FindFacts(ctx, workspaceID, store.FactQuery{
		EntityID: topic,
	})
}

// Semantic performs vector similarity search within a workspace.
func (mt *MemoryTools) Semantic(ctx context.Context, workspaceID string, embedding []float32, k int) ([]store.VectorResult, error) {
	return mt.vectorStore.Search(ctx, embedding, k, map[string]any{
		"workspace_id": workspaceID,
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// VectorStore manages Tier 4: embedding storage and semantic search.
type VectorStore interface {
	Store(ctx context.Context, id string, embedding []float32, metadata map[string]any) error
	Search(ctx context.Context, query []float32, k int, filters map[string]any) ([]VectorResult, error)
	Delete(ctx context.Context, ids []string) error
	Close() error
}

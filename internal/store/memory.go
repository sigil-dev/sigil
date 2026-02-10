// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import (
	"context"
	"time"
)

// MemoryStore groups the three non-vector memory subsystems.
type MemoryStore interface {
	Messages() MessageStore
	Summaries() SummaryStore
	Knowledge() KnowledgeStore
	Close() error
}

// MessageStore manages Tier 1: recent searchable messages (FTS5).
type MessageStore interface {
	Append(ctx context.Context, workspaceID string, msg *Message) error
	Search(ctx context.Context, workspaceID string, query string, opts SearchOpts) ([]*Message, error)
	GetRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Message, error)
	Count(ctx context.Context, workspaceID string) (int64, error)
	Trim(ctx context.Context, workspaceID string, keepLast int) (int64, error)
	Close() error
}

// SummaryStore manages Tier 2: LLM-generated compaction summaries.
type SummaryStore interface {
	Store(ctx context.Context, workspaceID string, summary *Summary) error
	GetByRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Summary, error)
	GetLatest(ctx context.Context, workspaceID string, n int) ([]*Summary, error)
	Close() error
}

// KnowledgeStore manages Tier 3: entities, facts, and relationships.
type KnowledgeStore interface {
	PutEntity(ctx context.Context, workspaceID string, entity *Entity) error
	GetEntity(ctx context.Context, workspaceID string, id string) (*Entity, error)
	FindEntities(ctx context.Context, workspaceID string, query EntityQuery) ([]*Entity, error)

	PutRelationship(ctx context.Context, rel *Relationship) error
	GetRelationships(ctx context.Context, entityID string, opts RelOpts) ([]*Relationship, error)

	PutFact(ctx context.Context, workspaceID string, fact *Fact) error
	FindFacts(ctx context.Context, workspaceID string, query FactQuery) ([]*Fact, error)

	Traverse(ctx context.Context, startID string, depth int, filter TraversalFilter) (*Graph, error)

	Close() error
}

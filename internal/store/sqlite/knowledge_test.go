// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store/sqlite"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigil-dev/sigil/internal/store"
)

func TestKnowledgeStore_Entities(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	entity := &store.Entity{
		ID:          "ent-1",
		WorkspaceID: "ws-1",
		Type:        "person",
		Name:        "Alice",
		Properties:  map[string]any{"role": "engineer"},
		CreatedAt:   time.Now(),
	}

	err = ks.PutEntity(ctx, "ws-1", entity)
	require.NoError(t, err)

	got, err := ks.GetEntity(ctx, "ws-1", "ent-1")
	require.NoError(t, err)
	assert.Equal(t, "Alice", got.Name)
	assert.Equal(t, "person", got.Type)

	entities, err := ks.FindEntities(ctx, "ws-1", store.EntityQuery{Type: "person"})
	require.NoError(t, err)
	assert.Len(t, entities, 1)
}

func TestKnowledgeStore_Relationships(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-rels")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	for _, e := range []*store.Entity{
		{ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now()},
		{ID: "bob", WorkspaceID: "ws-1", Type: "person", Name: "Bob", CreatedAt: time.Now()},
	} {
		err = ks.PutEntity(ctx, "ws-1", e)
		require.NoError(t, err)
	}

	rel := &store.Relationship{
		ID:     "rel-1",
		FromID: "alice",
		ToID:   "bob",
		Type:   "works_with",
	}
	err = ks.PutRelationship(ctx, rel)
	require.NoError(t, err)

	rels, err := ks.GetRelationships(ctx, "alice", store.RelOpts{Direction: "outgoing"})
	require.NoError(t, err)
	assert.Len(t, rels, 1)
	assert.Equal(t, "works_with", rels[0].Type)
}

func TestKnowledgeStore_Facts(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-facts")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	err = ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	fact := &store.Fact{
		ID:          "fact-1",
		WorkspaceID: "ws-1",
		EntityID:    "alice",
		Predicate:   "occupation",
		Value:       "software engineer",
		Confidence:  0.95,
		CreatedAt:   time.Now(),
	}
	err = ks.PutFact(ctx, "ws-1", fact)
	require.NoError(t, err)

	facts, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, facts, 1)
	assert.Equal(t, "software engineer", facts[0].Value)
}

func TestKnowledgeStore_Traverse(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-traverse")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	entities := []*store.Entity{
		{ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now()},
		{ID: "bob", WorkspaceID: "ws-1", Type: "person", Name: "Bob", CreatedAt: time.Now()},
		{ID: "charlie", WorkspaceID: "ws-1", Type: "person", Name: "Charlie", CreatedAt: time.Now()},
	}
	for _, e := range entities {
		require.NoError(t, ks.PutEntity(ctx, "ws-1", e))
	}
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r1", FromID: "alice", ToID: "bob", Type: "knows"}))
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r2", FromID: "bob", ToID: "charlie", Type: "knows"}))

	graph, err := ks.Traverse(ctx, "alice", 2, store.TraversalFilter{})
	require.NoError(t, err)
	assert.Len(t, graph.Entities, 3) // alice, bob, charlie
	assert.Len(t, graph.Relationships, 2)
}

// TestKnowledgeStore_PutFact_UpsertBehavior verifies that inserting a fact with the same
// (workspaceID, entityID, predicate, value) triple updates the existing row rather than
// creating a duplicate — exercising the ON CONFLICT upsert in the triples table.
func TestKnowledgeStore_PutFact_UpsertBehavior(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-upsert")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	err = ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Insert fact F1 with confidence 0.9.
	err = ks.PutFact(ctx, "ws-1", &store.Fact{
		ID:          "fact-upsert-1",
		WorkspaceID: "ws-1",
		EntityID:    "alice",
		Predicate:   "occupation",
		Value:       "engineer",
		Confidence:  0.9,
		CreatedAt:   time.Now(),
	})
	require.NoError(t, err)

	// Insert F2 — same triple, updated confidence 1.0.
	err = ks.PutFact(ctx, "ws-1", &store.Fact{
		ID:          "fact-upsert-2",
		WorkspaceID: "ws-1",
		EntityID:    "alice",
		Predicate:   "occupation",
		Value:       "engineer",
		Confidence:  1.0,
		CreatedAt:   time.Now(),
	})
	require.NoError(t, err)

	facts, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, facts, 1, "upsert should produce exactly one fact, not two")
	assert.Equal(t, 1.0, facts[0].Confidence, "confidence should reflect the updated value")
}

// TestKnowledgeStore_PutFacts_BatchInsert verifies that PutFacts stores all facts
// from a batch correctly and they are all retrievable afterwards.
func TestKnowledgeStore_PutFacts_BatchInsert(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-putfacts-batch")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	require.NoError(t, ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	}))

	facts := []*store.Fact{
		{
			ID: "f-1", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "occupation", Value: "engineer", Confidence: 0.9, CreatedAt: time.Now(),
		},
		{
			ID: "f-2", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "location", Value: "San Francisco", Confidence: 0.8, CreatedAt: time.Now(),
		},
		{
			ID: "f-3", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "language", Value: "Go", Confidence: 1.0, CreatedAt: time.Now(),
		},
	}

	err = ks.PutFacts(ctx, "ws-1", facts)
	require.NoError(t, err)

	stored, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, stored, 3)

	valueByPred := make(map[string]string, len(stored))
	for _, f := range stored {
		valueByPred[f.Predicate] = f.Value
	}
	assert.Equal(t, "engineer", valueByPred["occupation"])
	assert.Equal(t, "San Francisco", valueByPred["location"])
	assert.Equal(t, "Go", valueByPred["language"])
}

// TestKnowledgeStore_PutFacts_EmptySlice_Noop verifies that passing an empty
// slice to PutFacts returns no error and inserts zero rows.
func TestKnowledgeStore_PutFacts_EmptySlice_Noop(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-putfacts-empty")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	err = ks.PutFacts(ctx, "ws-1", []*store.Fact{})
	require.NoError(t, err)

	stored, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{})
	require.NoError(t, err)
	assert.Empty(t, stored)
}

// TestKnowledgeStore_PutFacts_AtomicRollback verifies that PutFacts rolls back
// all inserts when the operation fails, leaving zero committed facts.
func TestKnowledgeStore_PutFacts_AtomicRollback(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-putfacts-rollback")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)

	require.NoError(t, ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	}))

	// Close the store to make subsequent DB operations fail.
	require.NoError(t, ks.Close())

	facts := []*store.Fact{
		{
			ID: "f-1", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "occupation", Value: "engineer", Confidence: 0.9, CreatedAt: time.Now(),
		},
		{
			ID: "f-2", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "location", Value: "San Francisco", Confidence: 0.8, CreatedAt: time.Now(),
		},
	}

	err = ks.PutFacts(ctx, "ws-1", facts)
	require.Error(t, err, "PutFacts should fail when the database is closed")

	// Reopen to verify no facts were committed.
	ks2, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks2.Close() }()

	stored, err := ks2.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Empty(t, stored, "no facts should be committed after a failed PutFacts")
}

// TestKnowledgeStore_Traverse_StartNotFound tests that Traverse returns ErrNotFound
// when the starting entity doesn't exist.
func TestKnowledgeStore_Traverse_StartNotFound(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-traverse-start-missing")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	// Try to traverse from a non-existent entity
	_, err = ks.Traverse(ctx, "nonexistent", 2, store.TraversalFilter{})
	require.Error(t, err)
	assert.True(t, sigilerr.IsNotFound(err), "Should return not_found error when start entity doesn't exist")
}

// TestKnowledgeStore_Traverse_MaxDepth tests that MaxDepth in TraversalFilter
// properly limits traversal depth.
func TestKnowledgeStore_Traverse_MaxDepth(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-traverse-maxdepth")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	// Create a chain: alice -> bob -> charlie -> dave
	entities := []*store.Entity{
		{ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now()},
		{ID: "bob", WorkspaceID: "ws-1", Type: "person", Name: "Bob", CreatedAt: time.Now()},
		{ID: "charlie", WorkspaceID: "ws-1", Type: "person", Name: "Charlie", CreatedAt: time.Now()},
		{ID: "dave", WorkspaceID: "ws-1", Type: "person", Name: "Dave", CreatedAt: time.Now()},
	}
	for _, e := range entities {
		require.NoError(t, ks.PutEntity(ctx, "ws-1", e))
	}
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r1", FromID: "alice", ToID: "bob", Type: "knows"}))
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r2", FromID: "bob", ToID: "charlie", Type: "knows"}))
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r3", FromID: "charlie", ToID: "dave", Type: "knows"}))

	tests := []struct {
		name           string
		requestedDepth int
		maxDepth       int
		expectedNodes  []string
	}{
		{
			name:           "MaxDepth=1 limits to direct neighbors",
			requestedDepth: 10,
			maxDepth:       1,
			expectedNodes:  []string{"alice", "bob"},
		},
		{
			name:           "MaxDepth=2 limits to 2 hops",
			requestedDepth: 10,
			maxDepth:       2,
			expectedNodes:  []string{"alice", "bob", "charlie"},
		},
		{
			name:           "MaxDepth=0 means no limit (backward compatible)",
			requestedDepth: 10,
			maxDepth:       0,
			expectedNodes:  []string{"alice", "bob", "charlie", "dave"},
		},
		{
			name:           "MaxDepth caps requested depth when lower",
			requestedDepth: 3,
			maxDepth:       1,
			expectedNodes:  []string{"alice", "bob"},
		},
		{
			name:           "MaxDepth doesn't override when higher than requested",
			requestedDepth: 1,
			maxDepth:       5,
			expectedNodes:  []string{"alice", "bob"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, err := ks.Traverse(ctx, "alice", tt.requestedDepth, store.TraversalFilter{
				MaxDepth: tt.maxDepth,
			})
			require.NoError(t, err)

			// Extract entity IDs from result
			gotIDs := make([]string, len(graph.Entities))
			for i, e := range graph.Entities {
				gotIDs[i] = e.ID
			}

			assert.ElementsMatch(t, tt.expectedNodes, gotIDs,
				"Expected nodes %v but got %v", tt.expectedNodes, gotIDs)
		})
	}
}

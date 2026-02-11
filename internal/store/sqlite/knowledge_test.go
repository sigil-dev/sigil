// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.ErrorIs(t, err, store.ErrNotFound, "Should return ErrNotFound when start entity doesn't exist")
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

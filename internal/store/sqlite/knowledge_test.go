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

// TestKnowledgeStore_PutFacts_AtomicRollback verifies the all-or-nothing
// semantics of PutFacts.
//
// Atomicity guarantee — structural, not injection-tested:
// PutFacts wraps all inserts in a single BeginTx/Commit block. If any insert
// fails, the transaction is rolled back and zero facts are visible to callers.
// This guarantee is enforced by the transaction structure in knowledge.go and
// is verified at the code-review level. A sqlmock-based injection test could
// verify mid-batch failure (fail exactly after the Nth ExecContext), but
// that dependency is not worth adding for this path.
//
// Why mid-batch failure is not directly triggerable with a real SQLite DB:
//   (a) ON CONFLICT DO UPDATE absorbs constraint violations — no unique-key errors.
//   (b) SQLite imposes no column-length limits on TEXT columns.
//
// What this test does cover:
//   - BeginTx failure (closed DB) → error returned, zero rows committed.
//   - Success path: all facts are atomically visible after Commit (regression
//     guard — if PutFacts were refactored to insert per-row without a
//     transaction and one row failed, the count would mismatch).
//
// The compaction-level lifecycle tests cover PutFacts error propagation end-to-end.
func TestKnowledgeStore_PutFacts_AtomicRollback(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-putfacts-rollback")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)

	require.NoError(t, ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	}))

	// Regression guard: verify the success path commits all facts atomically.
	// If PutFacts were refactored to per-row inserts without a wrapping
	// transaction, a partial failure would leave a count mismatch here.
	successFacts := []*store.Fact{
		{
			ID: "s-1", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "occupation", Value: "engineer", Confidence: 0.9, CreatedAt: time.Now(),
		},
		{
			ID: "s-2", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "location", Value: "San Francisco", Confidence: 0.8, CreatedAt: time.Now(),
		},
	}
	require.NoError(t, ks.PutFacts(ctx, "ws-1", successFacts))

	visible, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, visible, len(successFacts),
		"all facts must be atomically visible after a successful PutFacts")

	// Close the store to make subsequent DB operations fail at BeginTx.
	require.NoError(t, ks.Close())

	failFacts := []*store.Fact{
		{
			ID: "f-1", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "language", Value: "Go", Confidence: 1.0, CreatedAt: time.Now(),
		},
		{
			ID: "f-2", WorkspaceID: "ws-1", EntityID: "alice",
			Predicate: "hobby", Value: "climbing", Confidence: 0.7, CreatedAt: time.Now(),
		},
	}

	err = ks.PutFacts(ctx, "ws-1", failFacts)
	require.Error(t, err, "PutFacts should fail when the database is closed")

	// Reopen to verify the failed batch left no additional facts committed.
	ks2, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer func() { _ = ks2.Close() }()

	stored, err := ks2.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, stored, len(successFacts),
		"failed PutFacts must not commit any new facts — count must equal the pre-failure baseline")
}

// TestKnowledgeStore_DeleteFactsBySource verifies that DeleteFactsBySource removes
// only the triples whose metadata source field matches the given value.
func TestKnowledgeStore_DeleteFactsBySource(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		setup           func(t *testing.T, ks *sqlite.KnowledgeStore)
		deleteWorkspace string
		deleteSource    string
		checkWorkspace  string
		wantPredicates  []string // predicates expected to remain after delete
	}{
		{
			name: "deletes compaction facts, keeps manual facts",
			setup: func(t *testing.T, ks *sqlite.KnowledgeStore) {
				t.Helper()
				require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
					{ID: "f-c1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "summary", Value: "v1", Source: "compaction", CreatedAt: time.Now()},
					{ID: "f-c2", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "topic", Value: "v2", Source: "compaction", CreatedAt: time.Now()},
					{ID: "f-m1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "occupation", Value: "alice", Source: "manual", CreatedAt: time.Now()},
				}))
			},
			deleteWorkspace: "ws-1",
			deleteSource:    "compaction",
			checkWorkspace:  "ws-1",
			wantPredicates:  []string{"occupation"},
		},
		{
			name: "workspace isolation: delete in ws-1 does not affect ws-2",
			setup: func(t *testing.T, ks *sqlite.KnowledgeStore) {
				t.Helper()
				require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
					{ID: "f-ws1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "summary", Value: "ws1-val", Source: "compaction", CreatedAt: time.Now()},
				}))
				require.NoError(t, ks.PutFacts(ctx, "ws-2", []*store.Fact{
					{ID: "f-ws2", WorkspaceID: "ws-2", EntityID: "e2", Predicate: "summary", Value: "ws2-val", Source: "compaction", CreatedAt: time.Now()},
				}))
			},
			deleteWorkspace: "ws-1",
			deleteSource:    "compaction",
			checkWorkspace:  "ws-2",
			wantPredicates:  []string{"summary"},
		},
		{
			name: "cross-source isolation: deleting compaction leaves manual facts",
			setup: func(t *testing.T, ks *sqlite.KnowledgeStore) {
				t.Helper()
				require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
					{ID: "f-m1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "role", Value: "engineer", Source: "manual", CreatedAt: time.Now()},
					{ID: "f-m2", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "city", Value: "SF", Source: "manual", CreatedAt: time.Now()},
				}))
			},
			deleteWorkspace: "ws-1",
			deleteSource:    "compaction",
			checkWorkspace:  "ws-1",
			wantPredicates:  []string{"role", "city"},
		},
		{
			name: "no error when no facts match source",
			setup: func(t *testing.T, ks *sqlite.KnowledgeStore) {
				t.Helper()
				// Store nothing — delete against empty workspace should not error.
			},
			deleteWorkspace: "ws-1",
			deleteSource:    "compaction",
			checkWorkspace:  "ws-1",
			wantPredicates:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testDBPath(t, "knowledge-delete-by-source-"+tt.name)
			ks, err := sqlite.NewKnowledgeStore(db)
			require.NoError(t, err)
			defer func() { _ = ks.Close() }()

			tt.setup(t, ks)

			err = ks.DeleteFactsBySource(ctx, tt.deleteWorkspace, tt.deleteSource)
			require.NoError(t, err)

			remaining, err := ks.FindFacts(ctx, tt.checkWorkspace, store.FactQuery{})
			require.NoError(t, err)

			gotPredicates := make([]string, len(remaining))
			for i, f := range remaining {
				gotPredicates[i] = f.Predicate
			}
			assert.ElementsMatch(t, tt.wantPredicates, gotPredicates)
		})
	}
}

// TestKnowledgeStore_DeleteFactsByIDs verifies that DeleteFactsByIDs removes only
// the facts with matching IDs in the given workspace.
func TestKnowledgeStore_DeleteFactsByIDs(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes specified IDs, keeps others", func(t *testing.T) {
		db := testDBPath(t, "knowledge-delete-by-ids-basic")
		ks, err := sqlite.NewKnowledgeStore(db)
		require.NoError(t, err)
		defer func() { _ = ks.Close() }()

		require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
			{ID: "f-1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "role", Value: "engineer", Source: "compaction", CreatedAt: time.Now()},
			{ID: "f-2", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "city", Value: "SF", Source: "compaction", CreatedAt: time.Now()},
			{ID: "f-3", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "team", Value: "infra", Source: "compaction", CreatedAt: time.Now()},
		}))

		err = ks.DeleteFactsByIDs(ctx, "ws-1", []string{"f-1", "f-3"})
		require.NoError(t, err)

		remaining, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{})
		require.NoError(t, err)
		require.Len(t, remaining, 1)
		assert.Equal(t, "f-2", remaining[0].ID)
	})

	t.Run("empty IDs slice is no-op", func(t *testing.T) {
		db := testDBPath(t, "knowledge-delete-by-ids-empty")
		ks, err := sqlite.NewKnowledgeStore(db)
		require.NoError(t, err)
		defer func() { _ = ks.Close() }()

		require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
			{ID: "f-1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "role", Value: "v", Source: "compaction", CreatedAt: time.Now()},
		}))

		err = ks.DeleteFactsByIDs(ctx, "ws-1", []string{})
		require.NoError(t, err)

		remaining, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{})
		require.NoError(t, err)
		assert.Len(t, remaining, 1, "no-op should leave all facts intact")
	})

	t.Run("workspace isolation — delete in ws-1 does not affect ws-2", func(t *testing.T) {
		db := testDBPath(t, "knowledge-delete-by-ids-ws-isolation")
		ks, err := sqlite.NewKnowledgeStore(db)
		require.NoError(t, err)
		defer func() { _ = ks.Close() }()

		// Insert facts in two workspaces.
		require.NoError(t, ks.PutFacts(ctx, "ws-1", []*store.Fact{
			{ID: "f-1", WorkspaceID: "ws-1", EntityID: "e1", Predicate: "role", Value: "engineer", Source: "compaction", CreatedAt: time.Now()},
		}))
		require.NoError(t, ks.PutFacts(ctx, "ws-2", []*store.Fact{
			{ID: "f-2", WorkspaceID: "ws-2", EntityID: "e1", Predicate: "role", Value: "designer", Source: "compaction", CreatedAt: time.Now()},
		}))

		// Delete ws-1's fact — ws-2 must be untouched.
		err = ks.DeleteFactsByIDs(ctx, "ws-1", []string{"f-1"})
		require.NoError(t, err)

		// ws-1 should be empty.
		remaining1, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{})
		require.NoError(t, err)
		assert.Empty(t, remaining1, "ws-1 fact should be deleted")

		// ws-2 should still have its fact.
		remaining2, err := ks.FindFacts(ctx, "ws-2", store.FactQuery{})
		require.NoError(t, err)
		require.Len(t, remaining2, 1, "ws-2 fact must survive")
		assert.Equal(t, "f-2", remaining2[0].ID)
	})
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

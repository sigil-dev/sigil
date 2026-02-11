// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryTools_Search(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	mt := agent.NewMemoryTools(ms, vs)

	ctx := context.Background()
	wsID := "ws-1"

	err := ms.messages.Append(ctx, wsID, &store.Message{
		ID:      "msg-1",
		Content: "Kubernetes cluster is running",
		Role:    store.MessageRoleAssistant,
	})
	require.NoError(t, err)

	err = ms.messages.Append(ctx, wsID, &store.Message{
		ID:      "msg-2",
		Content: "The weather is nice today",
		Role:    store.MessageRoleUser,
	})
	require.NoError(t, err)

	results, err := mt.Search(ctx, wsID, "Kubernetes")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "msg-1", results[0].ID)
	assert.Contains(t, results[0].Content, "Kubernetes")
}

func TestMemoryTools_GetSummary(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	mt := agent.NewMemoryTools(ms, vs)

	ctx := context.Background()
	wsID := "ws-1"

	now := time.Now().Truncate(time.Second)
	err := ms.summaries.Store(ctx, wsID, &store.Summary{
		ID:       "sum-1",
		FromTime: now.Add(-1 * time.Hour),
		ToTime:   now,
		Content:  "Summary of recent conversation",
	})
	require.NoError(t, err)

	results, err := mt.Summary(ctx, wsID, now.Add(-2*time.Hour), now.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sum-1", results[0].ID)
	assert.Equal(t, "Summary of recent conversation", results[0].Content)
}

func TestMemoryTools_Recall(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	mt := agent.NewMemoryTools(ms, vs)

	ctx := context.Background()
	wsID := "ws-1"

	err := ms.knowledge.PutFact(ctx, wsID, &store.Fact{
		ID:         "fact-1",
		EntityID:   "alice",
		Predicate:  "role",
		Value:      "engineer",
		Confidence: 0.95,
	})
	require.NoError(t, err)

	err = ms.knowledge.PutFact(ctx, wsID, &store.Fact{
		ID:         "fact-2",
		EntityID:   "bob",
		Predicate:  "role",
		Value:      "designer",
		Confidence: 0.9,
	})
	require.NoError(t, err)

	results, err := mt.Recall(ctx, wsID, "alice")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "fact-1", results[0].ID)
	assert.Equal(t, "alice", results[0].EntityID)
	assert.Equal(t, "engineer", results[0].Value)
}

func TestMemoryTools_Semantic(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	mt := agent.NewMemoryTools(ms, vs)

	ctx := context.Background()
	wsID := "ws-1"

	// Two vectors: one "about cats", one "about dogs".
	catVec := []float32{1.0, 0.0, 0.0}
	dogVec := []float32{0.0, 1.0, 0.0}

	err := vs.Store(ctx, "vec-cat", catVec, map[string]any{"workspace_id": wsID, "topic": "cats"})
	require.NoError(t, err)

	err = vs.Store(ctx, "vec-dog", dogVec, map[string]any{"workspace_id": wsID, "topic": "dogs"})
	require.NoError(t, err)

	// Query close to cat vector.
	query := []float32{0.9, 0.1, 0.0}
	results, err := mt.Semantic(ctx, wsID, query, 2)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "vec-cat", results[0].ID, "cat vector should be closest match")
	assert.Less(t, results[0].Score, results[1].Score, "first result should have lower distance")
}

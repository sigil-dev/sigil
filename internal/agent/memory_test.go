// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock MemoryStore and sub-stores ---

type mockMemoryStore struct {
	messages  *mockMessageStore
	summaries *mockSummaryStore
	knowledge *mockKnowledgeStore
}

func newMockMemoryStore() *mockMemoryStore {
	return &mockMemoryStore{
		messages:  &mockMessageStore{},
		summaries: &mockSummaryStore{},
		knowledge: &mockKnowledgeStore{},
	}
}

func (m *mockMemoryStore) Messages() store.MessageStore   { return m.messages }
func (m *mockMemoryStore) Summaries() store.SummaryStore   { return m.summaries }
func (m *mockMemoryStore) Knowledge() store.KnowledgeStore { return m.knowledge }
func (m *mockMemoryStore) Close() error                    { return nil }

// --- mockMessageStore ---

type mockMessageStore struct {
	msgs []*store.Message
}

func (m *mockMessageStore) Append(_ context.Context, _ string, msg *store.Message) error {
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *mockMessageStore) Search(_ context.Context, _ string, query string, _ store.SearchOpts) ([]*store.Message, error) {
	var results []*store.Message
	for _, msg := range m.msgs {
		if strings.Contains(msg.Content, query) {
			results = append(results, msg)
		}
	}
	return results, nil
}

func (m *mockMessageStore) GetRange(_ context.Context, _ string, _, _ time.Time) ([]*store.Message, error) {
	return nil, nil
}

func (m *mockMessageStore) Count(_ context.Context, _ string) (int64, error) {
	return int64(len(m.msgs)), nil
}

func (m *mockMessageStore) Trim(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

func (m *mockMessageStore) Close() error { return nil }

// --- mockSummaryStore ---

type mockSummaryStore struct {
	summaries []*store.Summary
}

func (m *mockSummaryStore) Store(_ context.Context, _ string, summary *store.Summary) error {
	m.summaries = append(m.summaries, summary)
	return nil
}

func (m *mockSummaryStore) GetByRange(_ context.Context, _ string, from, to time.Time) ([]*store.Summary, error) {
	var results []*store.Summary
	for _, s := range m.summaries {
		if !s.FromTime.Before(from) && !s.ToTime.After(to) {
			results = append(results, s)
		}
	}
	return results, nil
}

func (m *mockSummaryStore) GetLatest(_ context.Context, _ string, _ int) ([]*store.Summary, error) {
	return nil, nil
}

func (m *mockSummaryStore) Close() error { return nil }

// --- mockKnowledgeStore ---

type mockKnowledgeStore struct {
	facts []*store.Fact
}

func (m *mockKnowledgeStore) PutEntity(_ context.Context, _ string, _ *store.Entity) error {
	return nil
}

func (m *mockKnowledgeStore) GetEntity(_ context.Context, _ string, _ string) (*store.Entity, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) FindEntities(_ context.Context, _ string, _ store.EntityQuery) ([]*store.Entity, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) PutRelationship(_ context.Context, _ *store.Relationship) error {
	return nil
}

func (m *mockKnowledgeStore) GetRelationships(_ context.Context, _ string, _ store.RelOpts) ([]*store.Relationship, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) PutFact(_ context.Context, _ string, fact *store.Fact) error {
	m.facts = append(m.facts, fact)
	return nil
}

func (m *mockKnowledgeStore) FindFacts(_ context.Context, _ string, query store.FactQuery) ([]*store.Fact, error) {
	var results []*store.Fact
	for _, f := range m.facts {
		if query.EntityID != "" && f.EntityID != query.EntityID {
			continue
		}
		if query.Predicate != "" && f.Predicate != query.Predicate {
			continue
		}
		results = append(results, f)
	}
	return results, nil
}

func (m *mockKnowledgeStore) Traverse(_ context.Context, _ string, _ int, _ store.TraversalFilter) (*store.Graph, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) Close() error { return nil }

// --- mockVectorStore ---

type mockVectorStore struct {
	vectors map[string]mockVector
}

type mockVector struct {
	embedding []float32
	metadata  map[string]any
}

func newMockVectorStore() *mockVectorStore {
	return &mockVectorStore{vectors: make(map[string]mockVector)}
}

func (m *mockVectorStore) Store(_ context.Context, id string, embedding []float32, metadata map[string]any) error {
	m.vectors[id] = mockVector{embedding: embedding, metadata: metadata}
	return nil
}

func (m *mockVectorStore) Search(_ context.Context, query []float32, k int, filters map[string]any) ([]store.VectorResult, error) {
	type scored struct {
		id    string
		score float64
		meta  map[string]any
	}
	var candidates []scored

	for id, v := range m.vectors {
		// Apply workspace filter if present.
		if ws, ok := filters["workspace_id"]; ok {
			if vws, ok := v.metadata["workspace_id"]; ok {
				if ws != vws {
					continue
				}
			}
		}
		dist := cosineDistance(query, v.embedding)
		candidates = append(candidates, scored{id: id, score: dist, meta: v.metadata})
	}

	// Sort by score ascending (lower = more similar).
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score < candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	if k > len(candidates) {
		k = len(candidates)
	}

	results := make([]store.VectorResult, k)
	for i := 0; i < k; i++ {
		results[i] = store.VectorResult{
			ID:       candidates[i].id,
			Score:    candidates[i].score,
			Metadata: candidates[i].meta,
		}
	}
	return results, nil
}

func (m *mockVectorStore) Delete(_ context.Context, ids []string) error {
	for _, id := range ids {
		delete(m.vectors, id)
	}
	return nil
}

func (m *mockVectorStore) Close() error { return nil }

// cosineDistance returns 1 - cosine_similarity. Lower = more similar.
func cosineDistance(a, b []float32) float64 {
	if len(a) != len(b) {
		return 1.0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	if normA == 0 || normB == 0 {
		return 1.0
	}
	return 1.0 - dot/(math.Sqrt(normA)*math.Sqrt(normB))
}

// --- Tests ---

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

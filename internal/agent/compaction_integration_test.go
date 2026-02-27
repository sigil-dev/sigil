// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompaction_Compact_NoOpBelowThreshold(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "unused",
		facts:     []*store.Fact{{ID: "fact-unused"}},
		embedding: []float32{0.1, 0.2},
	}

	appendMessages(t, mem.messages, "ws-1", 4)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.SummariesCreated)
	assert.Equal(t, 0, result.FactsExtracted)
	assert.Equal(t, 0, result.MessagesProcessed)
	assert.Equal(t, int64(0), result.MessagesTrimmed)
	assert.Equal(t, 0, p.summarizeCalls)
	assert.Equal(t, 0, p.extractCalls)
	assert.Equal(t, 0, p.embedCalls)
	assert.Len(t, mem.summaries.summaries, 0)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_FullLifecycle_ExtractFactsEnabled(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary: "Summary: discussion about deployment and ownership",
		facts: []*store.Fact{
			{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95},
			{ID: "fact-2", EntityID: "project", Predicate: "status", Value: "active", Confidence: 0.90},
		},
		embedding: []float32{0.4, 0.3, 0.2},
	}

	appendMessages(t, mem.messages, "ws-1", 7)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.SummariesCreated)
	assert.Equal(t, 2, result.FactsExtracted)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, int64(5), result.MessagesTrimmed)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Equal(t, 1, p.extractCalls)
	assert.Equal(t, 1, p.embedCalls)

	require.Len(t, mem.summaries.summaries, 1)
	summary := mem.summaries.summaries[0]
	assert.Equal(t, "Summary: discussion about deployment and ownership", summary.Content)
	assert.Len(t, summary.MessageIDs, 5)
	assert.Equal(t, "msg-0", summary.MessageIDs[0])
	assert.Equal(t, "msg-4", summary.MessageIDs[4])

	require.Len(t, mem.knowledge.facts, 2)
	assert.Equal(t, "ws-1", mem.knowledge.facts[0].WorkspaceID)
	assert.Equal(t, "ws-1", mem.knowledge.facts[1].WorkspaceID)

	count, err := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "oldest compacted batch should be trimmed")

	require.Len(t, vec.vectors, 1)
	for _, v := range vec.vectors {
		assert.Equal(t, []float32{0.4, 0.3, 0.2}, v.embedding)
		assert.Equal(t, "ws-1", v.metadata["workspace_id"])
		assert.Equal(t, "summary", v.metadata["kind"])
	}
}

func TestCompaction_Compact_FullLifecycle_ExtractFactsDisabled(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "Summary without fact extraction",
		facts:     []*store.Fact{{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95}},
		embedding: []float32{0.8, 0.1},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.SummariesCreated)
	assert.Equal(t, 0, result.FactsExtracted)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, int64(5), result.MessagesTrimmed)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Equal(t, 0, p.extractCalls, "fact extraction should be skipped when disabled")
	assert.Equal(t, 1, p.embedCalls)
	assert.Len(t, mem.knowledge.facts, 0)
}

func TestCompaction_Compact_SummarizeProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summarizeErr: fmt.Errorf("summarize failed"),
		embedding:    []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Len(t, mem.summaries.summaries, 0)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_SummaryStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.summaries.storeErr = fmt.Errorf("summary store failed")
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_FactExtractionProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:    "summary",
		extractErr: fmt.Errorf("extract facts failed"),
		embedding:  []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.extractCalls)
	assert.Len(t, mem.summaries.summaries, 1, "summary is stored before extraction stage")
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_KnowledgeStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.knowledge.putFactErr = fmt.Errorf("knowledge store failed")
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary: "summary",
		facts: []*store.Fact{
			{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95},
		},
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          true,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_EmbeddingProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:  "summary",
		embedErr: fmt.Errorf("embed failed"),
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_VectorStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	vec.storeErr = fmt.Errorf("vector store failed")
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(5), count, "messages should not trim when vector storage fails")
}

func TestCompaction_Compact_DeleteByIDsFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.messages.deleteErr = fmt.Errorf("delete failed")
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, vec.vectors, 1)
}

func TestCompaction_Compact_PreservesMessageAppendedDuringCompaction(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
		summarizeHook: func() error {
			return mem.messages.Append(context.Background(), "ws-1", &store.Message{
				ID:        "msg-appended",
				Role:      store.MessageRoleUser,
				Content:   "appended while compacting",
				CreatedAt: time.Now().UTC(),
			})
		},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, int64(5), result.MessagesTrimmed)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(1), count, "newly appended message must be preserved")

	messages, rangeErr := mem.messages.GetRange(
		context.Background(),
		"ws-1",
		time.Time{},
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	)
	require.NoError(t, rangeErr)
	require.Len(t, messages, 1)
	assert.Equal(t, "msg-appended", messages[0].ID)
}

func TestCompaction_Compact_PreservesMessageAppendedAfterCountBeforeDelete(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	ss := newMockSessionStore()
	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)
	mem.messages.appendBeforeDelete = func() error {
		return mem.messages.Append(context.Background(), "ws-1", &store.Message{
			ID:        "msg-appended-after-count",
			Role:      store.MessageRoleUser,
			Content:   "appended after count before delete",
			CreatedAt: time.Now().UTC(),
		})
	}

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,
		SessionStore:          ss,
		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		ExtractFacts:          false,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, int64(5), result.MessagesTrimmed)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(1), count, "message appended after count must be preserved")

	messages, rangeErr := mem.messages.GetRange(
		context.Background(),
		"ws-1",
		time.Time{},
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	)
	require.NoError(t, rangeErr)
	require.Len(t, messages, 1)
	assert.Equal(t, "msg-appended-after-count", messages[0].ID)
}

type lifecycleMemoryStore struct {
	messages  *lifecycleMessageStore
	summaries *lifecycleSummaryStore
	knowledge *lifecycleKnowledgeStore
}

func newLifecycleMemoryStore() *lifecycleMemoryStore {
	return &lifecycleMemoryStore{
		messages:  &lifecycleMessageStore{},
		summaries: &lifecycleSummaryStore{},
		knowledge: &lifecycleKnowledgeStore{},
	}
}

func (m *lifecycleMemoryStore) Messages() store.MessageStore    { return m.messages }
func (m *lifecycleMemoryStore) Summaries() store.SummaryStore   { return m.summaries }
func (m *lifecycleMemoryStore) Knowledge() store.KnowledgeStore { return m.knowledge }
func (m *lifecycleMemoryStore) Close() error                    { return nil }

type lifecycleMessageStore struct {
	msgs         []*store.Message
	countErr     error
	getRangeErr  error
	deleteErr    error
	trimErr      error
	lastTrimKeep int
	appendBeforeDelete func() error
}

func (m *lifecycleMessageStore) Append(_ context.Context, _ string, msg *store.Message) error {
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *lifecycleMessageStore) Search(_ context.Context, _ string, _ string, _ store.SearchOpts) ([]*store.Message, error) {
	return nil, nil
}

func (m *lifecycleMessageStore) GetRange(_ context.Context, _ string, from, to time.Time) ([]*store.Message, error) {
	if m.getRangeErr != nil {
		return nil, m.getRangeErr
	}
	var inRange []*store.Message
	for _, msg := range m.msgs {
		if (msg.CreatedAt.Equal(from) || msg.CreatedAt.After(from)) && msg.CreatedAt.Before(to) {
			inRange = append(inRange, msg)
		}
	}
	sort.Slice(inRange, func(i, j int) bool {
		return inRange[i].CreatedAt.Before(inRange[j].CreatedAt)
	})
	return inRange, nil
}

func (m *lifecycleMessageStore) Count(_ context.Context, _ string) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.msgs)), nil
}

func (m *lifecycleMessageStore) Trim(_ context.Context, _ string, keepLast int) (int64, error) {
	if m.trimErr != nil {
		return 0, m.trimErr
	}
	if m.appendBeforeDelete != nil {
		if err := m.appendBeforeDelete(); err != nil {
			return 0, err
		}
		m.appendBeforeDelete = nil
	}
	m.lastTrimKeep = keepLast
	if keepLast < 0 {
		keepLast = 0
	}

	sort.Slice(m.msgs, func(i, j int) bool {
		return m.msgs[i].CreatedAt.Before(m.msgs[j].CreatedAt)
	})

	if keepLast >= len(m.msgs) {
		return 0, nil
	}

	toTrim := len(m.msgs) - keepLast
	m.msgs = append([]*store.Message(nil), m.msgs[toTrim:]...)
	return int64(toTrim), nil
}

func (m *lifecycleMessageStore) DeleteByIDs(_ context.Context, _ string, ids []string) (int64, error) {
	if m.deleteErr != nil {
		return 0, m.deleteErr
	}
	if m.appendBeforeDelete != nil {
		if err := m.appendBeforeDelete(); err != nil {
			return 0, err
		}
		m.appendBeforeDelete = nil
	}

	if len(ids) == 0 {
		return 0, nil
	}

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}

	var kept []*store.Message
	var deleted int64
	for _, msg := range m.msgs {
		if _, ok := idSet[msg.ID]; ok {
			deleted++
			continue
		}
		kept = append(kept, msg)
	}
	m.msgs = kept
	return deleted, nil
}

func (m *lifecycleMessageStore) Close() error { return nil }

type lifecycleSummaryStore struct {
	summaries []*store.Summary
	storeErr  error
}

func (s *lifecycleSummaryStore) Store(_ context.Context, _ string, summary *store.Summary) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.summaries = append(s.summaries, summary)
	return nil
}

func (s *lifecycleSummaryStore) GetByRange(_ context.Context, _ string, from, to time.Time) ([]*store.Summary, error) {
	var out []*store.Summary
	for _, summary := range s.summaries {
		if !summary.FromTime.Before(from) && !summary.ToTime.After(to) {
			out = append(out, summary)
		}
	}
	return out, nil
}

func (s *lifecycleSummaryStore) GetLatest(_ context.Context, _ string, n int) ([]*store.Summary, error) {
	if n <= 0 || len(s.summaries) == 0 {
		return nil, nil
	}

	sorted := append([]*store.Summary(nil), s.summaries...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n], nil
}

func (s *lifecycleSummaryStore) Close() error { return nil }

type lifecycleKnowledgeStore struct {
	facts      []*store.Fact
	putFactErr error
}

func (k *lifecycleKnowledgeStore) PutEntity(_ context.Context, _ string, _ *store.Entity) error { return nil }
func (k *lifecycleKnowledgeStore) GetEntity(_ context.Context, _ string, _ string) (*store.Entity, error) {
	return nil, nil
}
func (k *lifecycleKnowledgeStore) FindEntities(_ context.Context, _ string, _ store.EntityQuery) ([]*store.Entity, error) {
	return nil, nil
}
func (k *lifecycleKnowledgeStore) PutRelationship(_ context.Context, _ *store.Relationship) error { return nil }
func (k *lifecycleKnowledgeStore) GetRelationships(_ context.Context, _ string, _ store.RelOpts) ([]*store.Relationship, error) {
	return nil, nil
}

func (k *lifecycleKnowledgeStore) PutFact(_ context.Context, _ string, fact *store.Fact) error {
	if k.putFactErr != nil {
		return k.putFactErr
	}
	k.facts = append(k.facts, fact)
	return nil
}

func (k *lifecycleKnowledgeStore) FindFacts(_ context.Context, _ string, _ store.FactQuery) ([]*store.Fact, error) {
	return k.facts, nil
}

func (k *lifecycleKnowledgeStore) Traverse(_ context.Context, _ string, _ int, _ store.TraversalFilter) (*store.Graph, error) {
	return nil, nil
}

func (k *lifecycleKnowledgeStore) Close() error { return nil }

type lifecycleVector struct {
	embedding []float32
	metadata  map[string]any
}

type lifecycleVectorStore struct {
	vectors   map[string]lifecycleVector
	storeErr  error
	searchErr error
}

func newLifecycleVectorStore() *lifecycleVectorStore {
	return &lifecycleVectorStore{
		vectors: make(map[string]lifecycleVector),
	}
}

func (v *lifecycleVectorStore) Store(_ context.Context, id string, embedding []float32, metadata map[string]any) error {
	if v.storeErr != nil {
		return v.storeErr
	}
	v.vectors[id] = lifecycleVector{embedding: embedding, metadata: metadata}
	return nil
}

func (v *lifecycleVectorStore) Search(_ context.Context, _ []float32, _ int, _ map[string]any) ([]store.VectorResult, error) {
	if v.searchErr != nil {
		return nil, v.searchErr
	}
	return nil, nil
}

func (v *lifecycleVectorStore) Delete(_ context.Context, ids []string) error {
	for _, id := range ids {
		delete(v.vectors, id)
	}
	return nil
}

func (v *lifecycleVectorStore) Close() error { return nil }

type mockCompactionProvider struct {
	summary string
	facts   []*store.Fact

	embedding []float32

	summarizeErr error
	extractErr   error
	embedErr     error

	summarizeHook func() error

	summarizeCalls int
	extractCalls   int
	embedCalls     int
}

func (m *mockCompactionProvider) Summarize(_ context.Context, _ []*store.Message) (string, error) {
	m.summarizeCalls++
	if m.summarizeHook != nil {
		if err := m.summarizeHook(); err != nil {
			return "", err
		}
	}
	if m.summarizeErr != nil {
		return "", m.summarizeErr
	}
	return m.summary, nil
}

func (m *mockCompactionProvider) ExtractFacts(_ context.Context, _ string, _ []*store.Message) ([]*store.Fact, error) {
	m.extractCalls++
	if m.extractErr != nil {
		return nil, m.extractErr
	}
	return m.facts, nil
}

func (m *mockCompactionProvider) Embed(_ context.Context, _ string) ([]float32, error) {
	m.embedCalls++
	if m.embedErr != nil {
		return nil, m.embedErr
	}
	return m.embedding, nil
}

func appendMessages(t *testing.T, ms *lifecycleMessageStore, workspaceID string, n int) {
	t.Helper()

	now := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	for i := range n {
		err := ms.Append(context.Background(), workspaceID, &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("message %d", i),
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ---------------------------------------------------------------------------
// Session store mock
// ---------------------------------------------------------------------------

// mockSessionStore is an in-memory implementation of store.SessionStore for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*store.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*store.Session),
	}
}

func (m *mockSessionStore) CreateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; exists {
		return store.ErrConflict
	}

	// Store a copy to avoid aliasing.
	s := *session
	m.sessions[session.ID] = &s
	return nil
}

func (m *mockSessionStore) GetSession(_ context.Context, id string) (*store.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	cp := *s
	return &cp, nil
}

func (m *mockSessionStore) UpdateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return store.ErrNotFound
	}

	s := *session
	m.sessions[session.ID] = &s
	return nil
}

func (m *mockSessionStore) ListSessions(_ context.Context, workspaceID string, opts store.ListOpts) ([]*store.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*store.Session
	for _, s := range m.sessions {
		if s.WorkspaceID == workspaceID {
			cp := *s
			result = append(result, &cp)
		}
	}

	// Apply offset/limit.
	if opts.Offset > 0 {
		if opts.Offset >= len(result) {
			return nil, nil
		}
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

func (m *mockSessionStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[id]; !exists {
		return store.ErrNotFound
	}

	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) AppendMessage(_ context.Context, _ string, _ *store.Message) error {
	return nil
}

func (m *mockSessionStore) GetActiveWindow(_ context.Context, _ string, _ int) ([]*store.Message, error) {
	return nil, nil
}

// newMockSessionManager creates a SessionManager backed by an in-memory store.
func newMockSessionManager() *agent.SessionManager {
	return agent.NewSessionManager(newMockSessionStore())
}

// ---------------------------------------------------------------------------
// Provider / router mocks
// ---------------------------------------------------------------------------

// mockProvider returns a static "Hello, world!" chat response.
type mockProvider struct{}

func (p *mockProvider) Name() string             { return "mock" }
func (p *mockProvider) Available(_ context.Context) bool { return true }

func (p *mockProvider) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProvider) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Hello, "}
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "world!"}
	ch <- provider.ChatEvent{
		Type:  provider.EventTypeDone,
		Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5},
	}
	close(ch)
	return ch, nil
}

func (p *mockProvider) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock"}, nil
}

func (p *mockProvider) Close() error { return nil }

// mockProviderRouter routes all requests to a single provider.
type mockProviderRouter struct {
	provider provider.Provider
}

func (r *mockProviderRouter) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return r.provider, "mock-model", nil
}

func (r *mockProviderRouter) RegisterProvider(_ string, _ provider.Provider) error { return nil }
func (r *mockProviderRouter) Close() error                                        { return nil }

// newMockProviderRouter returns a Router that always responds with "Hello, world!".
func newMockProviderRouter() *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProvider{}}
}

// mockProviderRouterBudgetExceeded always returns a budget-exceeded error.
type mockProviderRouterBudgetExceeded struct{}

func (r *mockProviderRouterBudgetExceeded) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderBudgetExceeded, "budget exceeded for workspace")
}

func (r *mockProviderRouterBudgetExceeded) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterBudgetExceeded) Close() error { return nil }

// newMockProviderRouterWithBudgetExceeded returns a Router that always returns a budget error.
func newMockProviderRouterWithBudgetExceeded() *mockProviderRouterBudgetExceeded {
	return &mockProviderRouterBudgetExceeded{}
}

// ---------------------------------------------------------------------------
// Audit store mock
// ---------------------------------------------------------------------------

// mockAuditStore captures audit entries in a slice for assertions.
type mockAuditStore struct {
	mu      sync.Mutex
	entries []*store.AuditEntry
}

func newMockAuditStore() *mockAuditStore {
	return &mockAuditStore{}
}

func (s *mockAuditStore) Append(_ context.Context, entry *store.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *mockAuditStore) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Security enforcer helpers
// ---------------------------------------------------------------------------

// newMockEnforcer returns an enforcer that allows all tool:* capabilities.
func newMockEnforcer() *security.Enforcer {
	e := security.NewEnforcer(nil)
	e.RegisterPlugin("test-plugin", security.NewCapabilitySet("tool:*"), security.NewCapabilitySet())
	return e
}

// newMockEnforcerDenyAll returns an enforcer that denies all capabilities.
func newMockEnforcerDenyAll() *security.Enforcer {
	e := security.NewEnforcer(nil)
	e.RegisterPlugin("test-plugin", security.NewCapabilitySet(), security.NewCapabilitySet())
	return e
}

// ---------------------------------------------------------------------------
// Plugin executor mocks
// ---------------------------------------------------------------------------

// mockPluginExecutor returns a configurable result string.
type mockPluginExecutor struct {
	result string
}

func (m *mockPluginExecutor) ExecuteTool(_ context.Context, _, _, _ string) (string, error) {
	if m.result != "" {
		return m.result, nil
	}
	return "executed", nil
}

// newMockPluginManager returns a PluginExecutor that returns "executed".
func newMockPluginManager() *mockPluginExecutor {
	return &mockPluginExecutor{}
}

// newMockPluginManagerWithResult returns a PluginExecutor that returns the given result.
func newMockPluginManagerWithResult(result string) *mockPluginExecutor {
	return &mockPluginExecutor{result: result}
}

// mockPluginExecutorSlow sleeps for a configurable duration before returning.
type mockPluginExecutorSlow struct {
	delay time.Duration
}

func (m *mockPluginExecutorSlow) ExecuteTool(ctx context.Context, _, _, _ string) (string, error) {
	select {
	case <-time.After(m.delay):
		return "slow_result", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// newMockPluginManagerSlow returns a PluginExecutor that sleeps for d before returning.
func newMockPluginManagerSlow(d time.Duration) *mockPluginExecutorSlow {
	return &mockPluginExecutorSlow{delay: d}
}

// ---------------------------------------------------------------------------
// Memory store mocks
// ---------------------------------------------------------------------------

// mockMemoryStore aggregates the three memory sub-stores.
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

// ---------------------------------------------------------------------------
// Vector store mock
// ---------------------------------------------------------------------------

type mockVector struct {
	embedding []float32
	metadata  map[string]any
}

type mockVectorStore struct {
	vectors map[string]mockVector
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

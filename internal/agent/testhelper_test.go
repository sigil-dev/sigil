// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
)

// newDefaultScanner creates a RegexScanner with DefaultRules for testing.
func newDefaultScanner(t *testing.T) *scanner.RegexScanner {
	t.Helper()
	rules, err := scanner.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules: %v", err)
	}
	s, err := scanner.NewRegexScanner(rules)
	if err != nil {
		t.Fatalf("NewRegexScanner: %v", err)
	}
	return s
}

// defaultScannerModes returns the standard per-stage scanner modes used by most tests:
// block input, redact tools, redact output.
func defaultScannerModes() agent.ScannerModes {
	return agent.ScannerModes{
		Input:  types.ScannerModeBlock,
		Tool:   types.ScannerModeRedact,
		Output: types.ScannerModeRedact,
	}
}

// newTestLoopConfig creates a valid LoopConfig using standard test mocks:
// default session manager, permissive enforcer, "Hello, world!" provider router,
// default scanner, and default scanner modes. Callers can override individual
// fields on the returned config before passing it to NewLoop.
func newTestLoopConfig(t *testing.T) agent.LoopConfig {
	t.Helper()
	return agent.LoopConfig{
		SessionManager: newMockSessionManager(),
		Enforcer:       newMockEnforcer(),
		ProviderRouter: newMockProviderRouter(),
		Scanner:        newDefaultScanner(t),
		ScannerModes:   defaultScannerModes(),
		AuditStore:     newMockAuditStore(),
	}
}

// ---------------------------------------------------------------------------
// Session store mock
// ---------------------------------------------------------------------------

// mockSessionStore is an in-memory implementation of store.SessionStore for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*store.Session
	messages map[string][]*store.Message // sessionID -> messages
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*store.Session),
		messages: make(map[string][]*store.Message),
	}
}

func (m *mockSessionStore) CreateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; exists {
		return sigilerr.New(sigilerr.CodeStoreConflict, "session already exists")
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
		return nil, sigilerr.New(sigilerr.CodeStoreEntityNotFound, "session not found")
	}

	cp := *s
	return &cp, nil
}

func (m *mockSessionStore) UpdateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return sigilerr.New(sigilerr.CodeStoreEntityNotFound, "session not found")
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
		return sigilerr.New(sigilerr.CodeStoreEntityNotFound, "session not found")
	}

	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) AppendMessage(_ context.Context, sessionID string, msg *store.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy to avoid aliasing.
	msgCopy := *msg
	m.messages[sessionID] = append(m.messages[sessionID], &msgCopy)
	return nil
}

func (m *mockSessionStore) GetActiveWindow(_ context.Context, sessionID string, limit int) ([]*store.Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	msgs := m.messages[sessionID]
	if len(msgs) == 0 {
		return nil, nil
	}

	// Return up to limit messages from the end.
	start := 0
	if len(msgs) > limit {
		start = len(msgs) - limit
	}

	// Return copies to avoid aliasing.
	result := make([]*store.Message, 0, len(msgs)-start)
	for _, msg := range msgs[start:] {
		msgCopy := *msg
		result = append(result, &msgCopy)
	}
	return result, nil
}

// newMockSessionManager creates a SessionManager backed by an in-memory store.
func newMockSessionManager() *agent.SessionManager {
	return agent.NewSessionManager(newMockSessionStore())
}

// newMockSessionManagerWithStore returns both the manager and its backing store,
// allowing tests to manipulate session state directly (e.g., setting status to paused).
func newMockSessionManagerWithStore() (*agent.SessionManager, *mockSessionStore) {
	ss := newMockSessionStore()
	return agent.NewSessionManager(ss), ss
}

// setSessionStatus directly mutates a session's status in the mock store.
func (m *mockSessionStore) setSessionStatus(id string, status store.SessionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[id]; ok {
		s.Status = status
	}
}

// mockSessionStoreTracking wraps mockSessionStore and counts AppendMessage calls.
type mockSessionStoreTracking struct {
	mockSessionStore
	appendCount atomic.Int32
}

func newMockSessionStoreTracking() *mockSessionStoreTracking {
	return &mockSessionStoreTracking{
		mockSessionStore: mockSessionStore{
			sessions: make(map[string]*store.Session),
			messages: make(map[string][]*store.Message),
		},
	}
}

func (m *mockSessionStoreTracking) AppendMessage(ctx context.Context, sessionID string, msg *store.Message) error {
	m.appendCount.Add(1)
	return m.mockSessionStore.AppendMessage(ctx, sessionID, msg)
}

// ---------------------------------------------------------------------------
// Provider / router mocks
// ---------------------------------------------------------------------------

// mockProvider returns a static "Hello, world!" chat response.
type mockProvider struct{}

func (p *mockProvider) Name() string                     { return "mock" }
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

func (r *mockProviderRouter) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	return r.provider, "mock-model", nil
}

func (r *mockProviderRouter) RegisterProvider(_ string, _ provider.Provider) error { return nil }
func (r *mockProviderRouter) MaxAttempts() int                                     { return 1 }
func (r *mockProviderRouter) Close() error                                         { return nil }

// newMockProviderRouter returns a Router that always responds with "Hello, world!".
func newMockProviderRouter() *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProvider{}}
}

// mockProviderRouterBudgetExceeded always returns a budget-exceeded error.
type mockProviderRouterBudgetExceeded struct{}

func (r *mockProviderRouterBudgetExceeded) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderBudgetExceeded, "budget exceeded for workspace")
}

func (r *mockProviderRouterBudgetExceeded) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderBudgetExceeded, "budget exceeded for workspace")
}

func (r *mockProviderRouterBudgetExceeded) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterBudgetExceeded) MaxAttempts() int { return 1 }
func (r *mockProviderRouterBudgetExceeded) Close() error     { return nil }

// newMockProviderRouterWithBudgetExceeded returns a Router that always returns a budget error.
func newMockProviderRouterWithBudgetExceeded() *mockProviderRouterBudgetExceeded {
	return &mockProviderRouterBudgetExceeded{}
}

// mockProviderStreamError emits only an error event.
type mockProviderStreamError struct{}

func (p *mockProviderStreamError) Name() string                     { return "mock-error" }
func (p *mockProviderStreamError) Available(_ context.Context) bool { return true }

func (p *mockProviderStreamError) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderStreamError) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 1)
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: "upstream provider failure"}
	close(ch)
	return ch, nil
}

func (p *mockProviderStreamError) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-error"}, nil
}

func (p *mockProviderStreamError) Close() error { return nil }

// mockProviderStreamPartialThenError emits partial text then an error event.
type mockProviderStreamPartialThenError struct{}

func (p *mockProviderStreamPartialThenError) Name() string                     { return "mock-partial-error" }
func (p *mockProviderStreamPartialThenError) Available(_ context.Context) bool { return true }

func (p *mockProviderStreamPartialThenError) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderStreamPartialThenError) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Partial "}
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "response..."}
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: "connection lost mid-stream"}
	close(ch)
	return ch, nil
}

func (p *mockProviderStreamPartialThenError) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-partial-error"}, nil
}

func (p *mockProviderStreamPartialThenError) Close() error { return nil }

// newMockProviderRouterStreamError returns a Router with a provider that emits only error events.
func newMockProviderRouterStreamError() *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProviderStreamError{}}
}

// newMockProviderRouterStreamPartialThenError returns a Router with a provider that emits partial text then error.
func newMockProviderRouterStreamPartialThenError() *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProviderStreamPartialThenError{}}
}

// mockProviderCapturing records ChatRequest fields for test assertions.
type mockProviderCapturing struct {
	mu                   sync.Mutex
	capturedMessages     []provider.Message
	capturedSystemPrompt string
}

func (p *mockProviderCapturing) Name() string                     { return "mock-capturing" }
func (p *mockProviderCapturing) Available(_ context.Context) bool { return true }

func (p *mockProviderCapturing) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderCapturing) Chat(_ context.Context, req provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	p.capturedMessages = append([]provider.Message{}, req.Messages...)
	p.capturedSystemPrompt = req.SystemPrompt
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Response "}
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "text."}
	ch <- provider.ChatEvent{
		Type:  provider.EventTypeDone,
		Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5},
	}
	close(ch)
	return ch, nil
}

func (p *mockProviderCapturing) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-capturing"}, nil
}

func (p *mockProviderCapturing) Close() error { return nil }

func (p *mockProviderCapturing) getCapturedMessages() []provider.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]provider.Message{}, p.capturedMessages...)
}

// newMockProviderRouterCapturing returns a Router with a capturing provider.
func newMockProviderRouterCapturing(capturer *mockProviderCapturing) *mockProviderRouter {
	return &mockProviderRouter{provider: capturer}
}

// mockProviderRouterBudgetAware routes normally but enforces budget via RouteWithBudget.
// It also captures the budget passed to RouteWithBudget for assertions.
type mockProviderRouterBudgetAware struct {
	provider       provider.Provider
	mu             sync.Mutex
	capturedBudget *provider.Budget
}

func (r *mockProviderRouterBudgetAware) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return r.provider, "mock-model", nil
}

func (r *mockProviderRouterBudgetAware) RouteWithBudget(_ context.Context, _, _ string, budget *provider.Budget, _ []string) (provider.Provider, string, error) {
	r.mu.Lock()
	r.capturedBudget = budget
	r.mu.Unlock()
	if budget != nil && budget.MaxSessionTokens() > 0 && budget.UsedSessionTokens() >= budget.MaxSessionTokens() {
		return nil, "", sigilerr.New(sigilerr.CodeProviderBudgetExceeded, "budget exceeded")
	}
	return r.provider, "mock-model", nil
}

func (r *mockProviderRouterBudgetAware) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}
func (r *mockProviderRouterBudgetAware) MaxAttempts() int { return 1 }
func (r *mockProviderRouterBudgetAware) Close() error     { return nil }

func (r *mockProviderRouterBudgetAware) getCapturedBudget() *provider.Budget {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capturedBudget
}

// mockProviderRouterInvalidModelRef always returns an invalid-model-ref error.
type mockProviderRouterInvalidModelRef struct{}

func (r *mockProviderRouterInvalidModelRef) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderInvalidModelRef, "model name must use provider/model format")
}

func (r *mockProviderRouterInvalidModelRef) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderInvalidModelRef, "model name must use provider/model format")
}

func (r *mockProviderRouterInvalidModelRef) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}
func (r *mockProviderRouterInvalidModelRef) MaxAttempts() int { return 1 }
func (r *mockProviderRouterInvalidModelRef) Close() error     { return nil }

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

// mockAuditStoreError is an audit store that always returns an error from Append.
type mockAuditStoreError struct {
	appendCount atomic.Int32
	err         error
}

func (s *mockAuditStoreError) Append(_ context.Context, _ *store.AuditEntry) error {
	s.appendCount.Add(1)
	return s.err
}

func (s *mockAuditStoreError) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return nil, nil
}

// mockAuditStoreActionFilter is an audit store that fails only for entries whose
// Action matches one of the failActions prefixes. All other entries succeed.
// Used to test counter independence when multiple audit paths share a store.
type mockAuditStoreActionFilter struct {
	failActions []string
	err         error
}

func (s *mockAuditStoreActionFilter) Append(_ context.Context, entry *store.AuditEntry) error {
	for _, prefix := range s.failActions {
		if strings.HasPrefix(entry.Action, prefix) {
			return s.err
		}
	}
	return nil
}

func (s *mockAuditStoreActionFilter) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return nil, nil
}

// mockAuditStoreConditional is an audit store that fails for the first N calls,
// then succeeds. Used to test consecutive failure counter behavior.
type mockAuditStoreConditional struct {
	callCount          atomic.Int32
	failUntilCallCount int
}

func (s *mockAuditStoreConditional) Append(_ context.Context, _ *store.AuditEntry) error {
	current := s.callCount.Add(1)
	if int(current) <= s.failUntilCallCount {
		return fmt.Errorf("simulated audit failure (call %d of %d)", current, s.failUntilCallCount)
	}
	return nil
}

func (s *mockAuditStoreConditional) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Security enforcer helpers
// ---------------------------------------------------------------------------

// newMockEnforcer returns an enforcer that allows all tool:* capabilities.
func newMockEnforcer() *security.Enforcer {
	e := security.NewEnforcer(nil)
	e.RegisterPlugin("test-plugin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())
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

// newMockPluginManagerWithError returns a PluginExecutor that always returns the given error.
func newMockPluginManagerWithError(err error) *mockPluginExecutorError {
	return &mockPluginExecutorError{err: err}
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

func (m *mockMemoryStore) Messages() store.MessageStore    { return m.messages }
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

func (m *mockMessageStore) DeleteByIDs(_ context.Context, _ string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}

	filtered := m.msgs[:0]
	var deleted int64
	for _, msg := range m.msgs {
		if _, ok := idSet[msg.ID]; ok {
			deleted++
			continue
		}
		filtered = append(filtered, msg)
	}
	m.msgs = filtered

	return deleted, nil
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

// --- Error-returning mock variants ---

// mockMessageStoreError returns an error from Append.
type mockMessageStoreError struct {
	mockMessageStore
	appendErr error
}

func (m *mockMessageStoreError) Append(_ context.Context, _ string, _ *store.Message) error {
	return m.appendErr
}

// mockMessageStoreSearchError returns an error from Search.
type mockMessageStoreSearchError struct {
	mockMessageStore
	searchErr error
}

func (m *mockMessageStoreSearchError) Search(_ context.Context, _ string, _ string, _ store.SearchOpts) ([]*store.Message, error) {
	return nil, m.searchErr
}

// mockSummaryStoreError returns an error from GetByRange.
type mockSummaryStoreError struct {
	mockSummaryStore
	getByRangeErr error
}

func (m *mockSummaryStoreError) GetByRange(_ context.Context, _ string, _, _ time.Time) ([]*store.Summary, error) {
	return nil, m.getByRangeErr
}

// mockKnowledgeStoreError returns an error from FindFacts.
type mockKnowledgeStoreError struct {
	mockKnowledgeStore
	findFactsErr error
}

func (m *mockKnowledgeStoreError) FindFacts(_ context.Context, _ string, _ store.FactQuery) ([]*store.Fact, error) {
	return nil, m.findFactsErr
}

// mockVectorStoreError returns an error from Store.
type mockVectorStoreError struct {
	mockVectorStore
	storeErr error
}

func (m *mockVectorStoreError) Store(_ context.Context, _ string, _ []float32, _ map[string]any) error {
	return m.storeErr
}

// mockVectorStoreSearchError returns an error from Search.
type mockVectorStoreSearchError struct {
	mockVectorStore
	searchErr error
}

func (m *mockVectorStoreSearchError) Search(_ context.Context, _ []float32, _ int, _ map[string]any) ([]store.VectorResult, error) {
	return nil, m.searchErr
}

// mockMemoryStoreWithError wraps error-returning stores.
type mockMemoryStoreWithError struct {
	messages  store.MessageStore
	summaries store.SummaryStore
	knowledge store.KnowledgeStore
}

func (m *mockMemoryStoreWithError) Messages() store.MessageStore    { return m.messages }
func (m *mockMemoryStoreWithError) Summaries() store.SummaryStore   { return m.summaries }
func (m *mockMemoryStoreWithError) Knowledge() store.KnowledgeStore { return m.knowledge }
func (m *mockMemoryStoreWithError) Close() error                    { return nil }

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

// mockProviderStreamUsageThenError emits a text delta, usage event, then error event.
// Used to test that token accounting survives stream failures.
type mockProviderStreamUsageThenError struct{}

func (p *mockProviderStreamUsageThenError) Name() string                     { return "mock-usage-error" }
func (p *mockProviderStreamUsageThenError) Available(_ context.Context) bool { return true }

func (p *mockProviderStreamUsageThenError) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderStreamUsageThenError) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 4)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Partial "}
	ch <- provider.ChatEvent{Type: provider.EventTypeUsage, Usage: &provider.Usage{InputTokens: 30, OutputTokens: 20}}
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: "stream interrupted"}
	close(ch)
	return ch, nil
}

func (p *mockProviderStreamUsageThenError) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-usage-error"}, nil
}

func (p *mockProviderStreamUsageThenError) Close() error { return nil }

// newMockProviderRouterStreamUsageThenError returns a Router with a provider that emits usage then error.
func newMockProviderRouterStreamUsageThenError() *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProviderStreamUsageThenError{}}
}

// mockProviderCustomResponse returns a configurable text response.
type mockProviderCustomResponse struct {
	response string
}

func (p *mockProviderCustomResponse) Name() string                     { return "mock-custom" }
func (p *mockProviderCustomResponse) Available(_ context.Context) bool { return true }
func (p *mockProviderCustomResponse) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderCustomResponse) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 2)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: p.response}
	ch <- provider.ChatEvent{
		Type:  provider.EventTypeDone,
		Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5},
	}
	close(ch)
	return ch, nil
}

func (p *mockProviderCustomResponse) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-custom"}, nil
}
func (p *mockProviderCustomResponse) Close() error { return nil }

func newMockProviderRouterWithResponse(response string) *mockProviderRouter {
	return &mockProviderRouter{provider: &mockProviderCustomResponse{response: response}}
}

// ---------------------------------------------------------------------------
// Intermediate text with secret mock (for sigil-7g5.181 test)
// ---------------------------------------------------------------------------

// mockProviderIntermediateTextWithSecret emits text containing a secret
// alongside a tool call on the first Chat() call (simulating an intermediate
// assistant turn), then returns clean text on the second call.
type mockProviderIntermediateTextWithSecret struct {
	mu       sync.Mutex
	callNum  int
	secret   string
	toolCall *provider.ToolCall
}

func (p *mockProviderIntermediateTextWithSecret) Name() string                     { return "mock-intermediate" }
func (p *mockProviderIntermediateTextWithSecret) Available(_ context.Context) bool { return true }
func (p *mockProviderIntermediateTextWithSecret) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-intermediate"}, nil
}

func (p *mockProviderIntermediateTextWithSecret) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderIntermediateTextWithSecret) Close() error { return nil }

func (p *mockProviderIntermediateTextWithSecret) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 4)
	if call == 0 {
		// First call: emit text containing a secret alongside a tool call.
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Here is the key " + p.secret + ", let me use the tool."}
		ch <- provider.ChatEvent{
			Type:     provider.EventTypeToolCall,
			ToolCall: p.toolCall,
		}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5},
		}
	} else {
		// Subsequent calls: emit clean text response.
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Done."}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 20, OutputTokens: 3},
		}
	}
	close(ch)
	return ch, nil
}

// ---------------------------------------------------------------------------
// Error scanner mock
// ---------------------------------------------------------------------------

// mockErrorScanner always returns an error from Scan, simulating an internal
// scanner failure (e.g. OOM, regex engine panic, or other infrastructure fault).
type mockErrorScanner struct{}

func (s *mockErrorScanner) Scan(_ context.Context, _ string, _ scanner.ScanContext) (scanner.ScanResult, error) {
	return scanner.ScanResult{}, sigilerr.New(sigilerr.CodeSecurityScannerFailure, "internal scanner failure")
}

// mockOutputErrorScanner returns an error only when scanning the output stage,
// allowing input and tool scans to pass through cleanly.
type mockOutputErrorScanner struct{}

func (s *mockOutputErrorScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageOutput {
		return scanner.ScanResult{}, sigilerr.New(sigilerr.CodeSecurityScannerFailure, "internal scanner failure")
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockToolErrorScanner returns an error only when scanning the tool stage,
// allowing input scans to pass through cleanly so ProcessMessage reaches
// the tool execution path.
type mockToolErrorScanner struct{}

func (s *mockToolErrorScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageTool {
		return scanner.ScanResult{}, sigilerr.New(sigilerr.CodeSecurityScannerFailure, "internal scanner failure")
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockToolContentTooLargeScanner returns CodeSecurityScannerContentTooLarge on the tool
// stage when the content exceeds sizeThreshold bytes, then succeeds on re-scan with
// truncated content. This simulates a malicious tool returning oversized content to
// bypass scanning (sigil-7g5.184).
type mockToolContentTooLargeScanner struct {
	sizeThreshold int
	// scanCount tracks how many tool-stage Scan calls have been made.
	scanCount int
	// lastToolContent records the content of the most recent tool-stage scan.
	lastToolContent string
}

func (s *mockToolContentTooLargeScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage != types.ScanStageTool {
		return scanner.ScanResult{Content: content}, nil
	}
	s.scanCount++
	s.lastToolContent = content
	if len(content) > s.sizeThreshold {
		return scanner.ScanResult{Content: content},
			sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge,
				"content exceeds maximum length",
				sigilerr.Field("length", len(content)),
				sigilerr.Field("max_length", s.sizeThreshold),
			)
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockToolAlwaysContentTooLargeScanner returns CodeSecurityScannerContentTooLarge for
// every tool-stage Scan call, regardless of content length. This simulates a scanner
// whose internal size limit is smaller than maxToolContentScanSize (512KB), causing
// both the primary oversized scan AND the truncated re-scan to fail with the same
// error code (sigil-7g5.617). Input and output stages pass through cleanly so that
// ProcessMessage can reach the tool execution path.
type mockToolAlwaysContentTooLargeScanner struct {
	// scanCount tracks the total number of tool-stage Scan calls made.
	scanCount int
}

func (s *mockToolAlwaysContentTooLargeScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage != types.ScanStageTool {
		return scanner.ScanResult{Content: content}, nil
	}
	s.scanCount++
	return scanner.ScanResult{Content: content},
		sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge,
			"content exceeds scanner internal limit",
			sigilerr.Field("length", len(content)),
		)
}

// mockToolOversizedThenThreatScanner simulates the sigil-7g5.763 path: the first
// tool-stage Scan call returns CodeSecurityScannerContentTooLarge (content too large),
// and the second call (re-scan of truncated content) returns a threat match. All other
// stages pass through cleanly so ProcessMessage can reach the tool execution path.
type mockToolOversizedThenThreatScanner struct {
	mu        sync.Mutex
	toolCalls int
}

func (s *mockToolOversizedThenThreatScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage != types.ScanStageTool {
		return scanner.ScanResult{Content: content}, nil
	}
	s.mu.Lock()
	call := s.toolCalls
	s.toolCalls++
	s.mu.Unlock()
	if call == 0 {
		// Primary scan: content is oversized — return content_too_large.
		return scanner.ScanResult{Content: content},
			sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge, "content exceeds maximum length")
	}
	// Re-scan of truncated content: return a threat match (injection pattern detected).
	m, _ := scanner.NewMatch("injection-pattern", 0, len(content), scanner.SeverityHigh)
	return scanner.ScanResult{
		Threat:  true,
		Matches: []scanner.Match{m},
		Content: content,
	}, nil
}

// mockCancelledScanner checks ctx.Err() and returns CodeSecurityScannerCancelled
// when the context is already cancelled. This simulates the RegexScanner's
// context-cancellation path so loop tests can verify error code propagation
// without depending on the real scanner's timing.
type mockCancelledScanner struct{}

func (s *mockCancelledScanner) Scan(ctx context.Context, _ string, _ scanner.ScanContext) (scanner.ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return scanner.ScanResult{}, sigilerr.Wrap(err, sigilerr.CodeSecurityScannerCancelled, "scan cancelled")
	}
	return scanner.ScanResult{}, nil
}

// mockOutputCancelledScanner passes input scans cleanly and checks ctx.Err() only
// on the output stage, returning CodeSecurityScannerCancelled when the context is
// cancelled. This lets tests verify that output-stage cancellation propagates the
// correct error code without the input scan firing first.
type mockOutputCancelledScanner struct{}

func (s *mockOutputCancelledScanner) Scan(ctx context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageOutput {
		if err := ctx.Err(); err != nil {
			return scanner.ScanResult{}, sigilerr.Wrap(err, sigilerr.CodeSecurityScannerCancelled, "scan cancelled")
		}
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockToolCancelledScanner passes input and output scans cleanly and checks
// ctx.Err() only on the tool stage, returning CodeSecurityScannerCancelled when
// the context is cancelled. This lets tests verify that tool-stage cancellation
// propagates the correct error code without earlier stages firing first.
type mockToolCancelledScanner struct{}

func (s *mockToolCancelledScanner) Scan(ctx context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageTool {
		if err := ctx.Err(); err != nil {
			return scanner.ScanResult{}, sigilerr.Wrap(err, sigilerr.CodeSecurityScannerCancelled, "scan cancelled")
		}
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockInputContentTooLargeScanner returns CodeSecurityScannerContentTooLarge on the
// input stage unconditionally, simulating a scanner that always rejects input due to
// excessive size. All other stages pass through cleanly.
type mockInputContentTooLargeScanner struct{}

func (s *mockInputContentTooLargeScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageInput {
		return scanner.ScanResult{Content: content},
			sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge,
				"input content exceeds maximum length",
			)
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockOutputContentTooLargeScanner returns CodeSecurityScannerContentTooLarge on the
// output stage unconditionally, simulating a scanner that rejects LLM responses due to
// excessive size. Input scans pass through cleanly so ProcessMessage reaches the output
// scanning stage.
type mockOutputContentTooLargeScanner struct{}

func (s *mockOutputContentTooLargeScanner) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage == types.ScanStageOutput {
		return scanner.ScanResult{Content: content},
			sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge,
				"output content exceeds maximum length",
			)
	}
	return scanner.ScanResult{Content: content}, nil
}

// mockToolErrorScannerToggleable errors on tool-stage scans until succeedAfter
// tool-stage calls have been made, then succeeds. This allows testing the
// circuit-breaker reset behavior. Thread-safe via atomic counter.
type mockToolErrorScannerToggleable struct {
	toolCalls    atomic.Int64
	succeedAfter int64 // tool-stage call number (1-indexed) at which to start succeeding
}

func (s *mockToolErrorScannerToggleable) Scan(_ context.Context, content string, opts scanner.ScanContext) (scanner.ScanResult, error) {
	if opts.Stage != types.ScanStageTool {
		return scanner.ScanResult{Content: content}, nil
	}
	n := s.toolCalls.Add(1)
	if n >= s.succeedAfter {
		return scanner.ScanResult{Content: content}, nil
	}
	return scanner.ScanResult{}, fmt.Errorf("internal scanner failure (call %d)", n)
}

// mockProviderRepeatingToolCall emits a tool call on every even Chat() call
// (0, 2, 4, ...) and a text response on every odd call (1, 3, 5, ...).
// This allows testing scenarios that require multiple ProcessMessage calls
// each triggering a tool dispatch (each ProcessMessage uses two Chat() calls:
// one returning a tool call and one returning text).
type mockProviderRepeatingToolCall struct {
	mu       sync.Mutex
	callNum  int
	toolCall *provider.ToolCall
}

func (p *mockProviderRepeatingToolCall) Name() string                     { return "mock-repeating-tool" }
func (p *mockProviderRepeatingToolCall) Available(_ context.Context) bool { return true }
func (p *mockProviderRepeatingToolCall) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-repeating-tool"}, nil
}

func (p *mockProviderRepeatingToolCall) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderRepeatingToolCall) Close() error { return nil }

func (p *mockProviderRepeatingToolCall) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 4)
	if call%2 == 0 {
		ch <- provider.ChatEvent{
			Type:     provider.EventTypeToolCall,
			ToolCall: p.toolCall,
		}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2},
		}
	} else {
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Tool result processed."}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 20, OutputTokens: 8},
		}
	}
	close(ch)
	return ch, nil
}

// mockProviderBatchToolCall emits all provided tool calls in a single first Chat() response,
// then a text response on all subsequent calls. This allows testing scenarios where multiple
// tool scans occur within a single tool-loop iteration (i.e., within one turn).
type mockProviderBatchToolCall struct {
	mu        sync.Mutex
	callNum   int
	toolCalls []*provider.ToolCall
}

func (p *mockProviderBatchToolCall) Name() string                     { return "mock-batch-tool" }
func (p *mockProviderBatchToolCall) Available(_ context.Context) bool { return true }
func (p *mockProviderBatchToolCall) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-batch-tool"}, nil
}

func (p *mockProviderBatchToolCall) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderBatchToolCall) Close() error { return nil }

func (p *mockProviderBatchToolCall) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, len(p.toolCalls)+2)
	if call == 0 {
		// First call: emit all tool calls in one response.
		for _, tc := range p.toolCalls {
			ch <- provider.ChatEvent{
				Type:     provider.EventTypeToolCall,
				ToolCall: tc,
			}
		}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2},
		}
	} else {
		// Subsequent calls: emit a text response.
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "All tools processed."}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 20, OutputTokens: 8},
		}
	}
	close(ch)
	return ch, nil
}

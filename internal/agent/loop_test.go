// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock provider router ---

type mockProviderRouter struct {
	provider provider.Provider
}

func (r *mockProviderRouter) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return r.provider, "mock-model", nil
}

func (r *mockProviderRouter) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouter) Close() error { return nil }

// --- Mock provider ---

type mockProvider struct{}

func (p *mockProvider) Name() string { return "mock" }

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

// --- Mock provider router that returns a budget error ---

type mockProviderRouterBudgetExceeded struct{}

func (r *mockProviderRouterBudgetExceeded) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", sigilerr.New(sigilerr.CodeProviderBudgetExceeded, "budget exceeded for workspace")
}

func (r *mockProviderRouterBudgetExceeded) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterBudgetExceeded) Close() error { return nil }

// --- Mock audit store ---

type mockAuditStore struct {
	mu      sync.Mutex
	entries []*store.AuditEntry
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

// --- Tests ---

func TestAgentLoop_ProcessMessage(t *testing.T) {
	sessionStore := newMockSessionStore()
	sm := agent.NewSessionManager(sessionStore)
	ctx := context.Background()

	// Create a session to use.
	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: &mockProvider{}},
		AuditStore:     &mockAuditStore{},
	})

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "Hi there",
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	assert.Equal(t, session.ID, out.SessionID)
	assert.NotEmpty(t, out.Content, "response content should not be empty")
	assert.Contains(t, out.Content, "Hello, world!")
	assert.NotNil(t, out.Usage)
	assert.Equal(t, 10, out.Usage.InputTokens)
	assert.Equal(t, 5, out.Usage.OutputTokens)
}

func TestAgentLoop_StepsExecuteInOrder(t *testing.T) {
	sessionStore := newMockSessionStore()
	sm := agent.NewSessionManager(sessionStore)
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	var mu sync.Mutex
	var steps []string
	record := func(name string) func() {
		return func() {
			mu.Lock()
			defer mu.Unlock()
			steps = append(steps, name)
		}
	}

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: &mockProvider{}},
		AuditStore:     &mockAuditStore{},
		Hooks: &agent.LoopHooks{
			OnReceive:  record("receive"),
			OnPrepare:  record("prepare"),
			OnCallLLM:  record("call_llm"),
			OnProcess:  record("process"),
			OnRespond:  record("respond"),
			OnAudit:    record("audit"),
		},
	})

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "test order",
	})
	require.NoError(t, err)

	expected := []string{"receive", "prepare", "call_llm", "process", "respond", "audit"}
	assert.Equal(t, expected, steps)
}

func TestAgentLoop_BudgetEnforcement(t *testing.T) {
	sessionStore := newMockSessionStore()
	sm := agent.NewSessionManager(sessionStore)
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouterBudgetExceeded{},
		AuditStore:     &mockAuditStore{},
	})

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded), "expected budget exceeded error code")
}

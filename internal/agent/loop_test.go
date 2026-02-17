// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentLoop_ProcessMessage(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	// Create a session to use.
	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

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
	sm := newMockSessionManager()
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

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		Hooks: &agent.LoopHooks{
			OnReceive: record("receive"),
			OnPrepare: record("prepare"),
			OnCallLLM: record("call_llm"),
			OnProcess: record("process"),
			OnRespond: record("respond"),
			OnAudit:   record("audit"),
		},
	})
	require.NoError(t, err)

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

func TestAgentLoop_SessionBoundaryValidation(t *testing.T) {
	tests := []struct {
		name        string
		sessionWS   string
		sessionUser string
		msgWS       string
		msgUser     string
		wantCode    sigilerr.Code
		wantSubstr  string
	}{
		{
			name:        "workspace mismatch",
			sessionWS:   "ws-owner",
			sessionUser: "user-1",
			msgWS:       "ws-attacker",
			msgUser:     "user-1",
			wantCode:    sigilerr.CodeAgentSessionBoundaryMismatch,
			wantSubstr:  "workspace mismatch",
		},
		{
			name:        "user mismatch",
			sessionWS:   "ws-1",
			sessionUser: "user-owner",
			msgWS:       "ws-1",
			msgUser:     "user-attacker",
			wantCode:    sigilerr.CodeAgentSessionBoundaryMismatch,
			wantSubstr:  "user mismatch",
		},
		{
			name:        "both workspace and user mismatch",
			sessionWS:   "ws-owner",
			sessionUser: "user-owner",
			msgWS:       "ws-attacker",
			msgUser:     "user-attacker",
			wantCode:    sigilerr.CodeAgentSessionBoundaryMismatch,
			wantSubstr:  "workspace mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionManager()
			ctx := context.Background()

			session, err := sm.Create(ctx, tt.sessionWS, tt.sessionUser)
			require.NoError(t, err)

			loop, err := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
				Enforcer:       newMockEnforcer(),
			})
			require.NoError(t, err)

			out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
				SessionID:   session.ID,
				WorkspaceID: tt.msgWS,
				UserID:      tt.msgUser,
				Content:     "hello",
			})
			require.Error(t, err)
			assert.Nil(t, out)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected error code %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
			assert.Contains(t, err.Error(), tt.wantSubstr)
		})
	}
}

func TestAgentLoop_SessionStatusValidation(t *testing.T) {
	tests := []struct {
		name       string
		status     store.SessionStatus
		wantCode   sigilerr.Code
		wantSubstr string
	}{
		{
			name:       "archived session rejected",
			status:     store.SessionStatusArchived,
			wantCode:   sigilerr.CodeAgentSessionInactive,
			wantSubstr: "archived",
		},
		{
			name:       "paused session rejected",
			status:     store.SessionStatusPaused,
			wantCode:   sigilerr.CodeAgentSessionInactive,
			wantSubstr: "paused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, ss := newMockSessionManagerWithStore()
			ctx := context.Background()

			session, err := sm.Create(ctx, "ws-1", "user-1")
			require.NoError(t, err)

			// Mutate the session status directly in the backing store.
			ss.setSessionStatus(session.ID, tt.status)

			loop, err := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
				Enforcer:       newMockEnforcer(),
			})
			require.NoError(t, err)

			out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
				SessionID:   session.ID,
				WorkspaceID: "ws-1",
				UserID:      "user-1",
				Content:     "hello",
			})
			require.Error(t, err)
			assert.Nil(t, out)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected error code %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
			assert.Contains(t, err.Error(), tt.wantSubstr)
		})
	}
}

func TestAgentLoop_SessionBoundaryCheckedBeforeStoreWrite(t *testing.T) {
	// This test verifies that a workspace-mismatched message does NOT result
	// in any AppendMessage call — i.e., the boundary check runs before writes.
	ss := newMockSessionStoreTracking()
	sm := agent.NewSessionManager(ss)
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-owner", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-attacker",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Equal(t, int32(0), ss.appendCount.Load(), "AppendMessage must not be called when boundary check fails")
}

func TestAgentLoop_BudgetEnforcement(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterWithBudgetExceeded(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

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

func TestAgentLoop_ProviderStreamErrorOnly(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterStreamError(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err, "ProcessMessage should return error when stream emits error event")
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderUpstreamFailure),
		"expected CodeProviderUpstreamFailure, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "upstream provider failure")

	// Verify no assistant message was persisted.
	history, err := ss.GetActiveWindow(ctx, session.ID, 10)
	require.NoError(t, err)
	// Should only have the user message, not an assistant message.
	for _, msg := range history {
		assert.NotEqual(t, "assistant", msg.Role, "assistant message should not be persisted after stream error")
	}
}

func TestAgentLoop_ProviderStreamPartialTextThenError(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterStreamPartialThenError(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err, "ProcessMessage should return error when stream emits error after partial text")
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderUpstreamFailure),
		"expected CodeProviderUpstreamFailure, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "connection lost mid-stream")

	// Verify no assistant message was persisted (partial text discarded).
	history, err := ss.GetActiveWindow(ctx, session.ID, 10)
	require.NoError(t, err)
	// Should only have the user message, not an assistant message.
	for _, msg := range history {
		assert.NotEqual(t, "assistant", msg.Role, "assistant message should not be persisted after stream error")
	}
}

func TestAgentLoop_NoDuplicateUserMessage(t *testing.T) {
	// This test verifies that the user message appears exactly once in the
	// provider's message array, not duplicated.
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	capturer := &mockProviderCapturing{}
	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterCapturing(capturer),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "test message",
	})
	require.NoError(t, err)

	messages := capturer.getCapturedMessages()
	require.NotEmpty(t, messages, "provider should have received messages")

	// Count how many times the user message "test message" appears.
	userMsgCount := 0
	for _, msg := range messages {
		if msg.Role == store.MessageRoleUser && msg.Content == "test message" {
			userMsgCount++
		}
	}

	assert.Equal(t, 1, userMsgCount, "user message should appear exactly once, not duplicated")

	// System prompt should be sent via ChatRequest.SystemPrompt, not as a message.
	assert.NotEmpty(t, capturer.capturedSystemPrompt, "system prompt should be set")
	assert.Equal(t, "You are a helpful assistant.", capturer.capturedSystemPrompt)

	// Messages should not contain a system role message; first message should be user.
	for _, msg := range messages {
		assert.NotEqual(t, store.MessageRoleSystem, msg.Role, "system prompt should not be in messages array")
	}
	assert.Equal(t, store.MessageRoleUser, messages[0].Role, "first message should be user message")
	assert.Equal(t, "test message", messages[0].Content, "user message content should match")
}

// ---------------------------------------------------------------------------
// Invalid input and error propagation tests
// ---------------------------------------------------------------------------

func TestAgentLoop_InvalidInputCombinations(t *testing.T) {
	tests := []struct {
		name       string
		msg        agent.InboundMessage
		wantCode   sigilerr.Code
		wantSubstr string
	}{
		{
			name: "empty SessionID",
			msg: agent.InboundMessage{
				SessionID:   "",
				WorkspaceID: "ws-1",
				UserID:      "user-1",
				Content:     "hello",
			},
			wantCode:   sigilerr.CodeAgentLoopInvalidInput,
			wantSubstr: "SessionID",
		},
		{
			name: "empty WorkspaceID",
			msg: agent.InboundMessage{
				SessionID:   "sess-1",
				WorkspaceID: "",
				UserID:      "user-1",
				Content:     "hello",
			},
			wantCode:   sigilerr.CodeAgentLoopInvalidInput,
			wantSubstr: "WorkspaceID",
		},
		{
			name: "empty UserID",
			msg: agent.InboundMessage{
				SessionID:   "sess-1",
				WorkspaceID: "ws-1",
				UserID:      "",
				Content:     "hello",
			},
			wantCode:   sigilerr.CodeAgentLoopInvalidInput,
			wantSubstr: "UserID",
		},
		{
			name: "empty Content",
			msg: agent.InboundMessage{
				SessionID:   "sess-1",
				WorkspaceID: "ws-1",
				UserID:      "user-1",
				Content:     "",
			},
			wantCode:   sigilerr.CodeAgentLoopInvalidInput,
			wantSubstr: "Content",
		},
		{
			name: "all fields empty",
			msg: agent.InboundMessage{
				SessionID:   "",
				WorkspaceID: "",
				UserID:      "",
				Content:     "",
			},
			wantCode:   sigilerr.CodeAgentLoopInvalidInput,
			wantSubstr: "missing required fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loop, err := agent.NewLoop(agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
				Enforcer:       newMockEnforcer(),
			})
			require.NoError(t, err)

			out, err := loop.ProcessMessage(context.Background(), tt.msg)
			require.Error(t, err)
			assert.Nil(t, out)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected error code %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
			assert.Contains(t, err.Error(), tt.wantSubstr)
		})
	}
}

func TestAgentLoop_SessionNotFound(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   "nonexistent-session",
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	// The error should be a not-found error from the session store,
	// wrapped by the agent loop. Since oops.Code() returns the deepest
	// code in the chain, the store's not-found code is visible.
	assert.True(t, sigilerr.IsNotFound(err),
		"expected not-found error, got code %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "prepare")
}

func TestAgentLoop_AppendMessageFailure(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Wrap the store with one that fails on AppendMessage.
	failingStore := &mockSessionStoreAppendError{
		mockSessionStore: ss,
		appendErr:        assert.AnError,
	}
	sm = agent.NewSessionManager(failingStore)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopFailure),
		"expected CodeAgentLoopFailure, got %s", sigilerr.CodeOf(err))
}

func TestAgentLoop_GetActiveWindowFailure(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Wrap the store with one that fails on GetActiveWindow.
	failingStore := &mockSessionStoreWindowError{
		mockSessionStore: ss,
		windowErr:        assert.AnError,
	}
	sm = agent.NewSessionManager(failingStore)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopFailure),
		"expected CodeAgentLoopFailure, got %s", sigilerr.CodeOf(err))
}

func TestAgentLoop_ProviderChatFailure(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Provider whose Chat() method returns an error.
	router := &mockProviderRouter{
		provider: &mockProviderChatError{},
	}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderUpstreamFailure),
		"expected CodeProviderUpstreamFailure, got %s", sigilerr.CodeOf(err))
}

func TestAgentLoop_RouterNonBudgetFailure(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Router that returns a generic error (not budget-exceeded).
	router := &mockProviderRouterGenericError{}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderAllUnavailable),
		"expected CodeProviderAllUnavailable, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "all providers failed")
}

func TestAgentLoop_BudgetWiredThroughSessionTokens(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Set session token budget — within limits.
	session.TokenBudget.MaxPerSession = 10000
	session.TokenBudget.UsedSession = 500
	require.NoError(t, ss.UpdateSession(ctx, session))

	budgetRouter := &mockProviderRouterBudgetAware{provider: &mockProvider{}}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: budgetRouter,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// Verify the router received the session's budget.
	captured := budgetRouter.getCapturedBudget()
	require.NotNil(t, captured, "RouteWithBudget should have been called with a budget")
	assert.Equal(t, 10000, captured.MaxSessionTokens())
	assert.Equal(t, 500, captured.UsedSessionTokens())
}

func TestAgentLoop_BudgetWiredEnforcesLimit(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Set session token budget — exceeded.
	session.TokenBudget.MaxPerSession = 1000
	session.TokenBudget.UsedSession = 1000
	require.NoError(t, ss.UpdateSession(ctx, session))

	budgetRouter := &mockProviderRouterBudgetAware{provider: &mockProvider{}}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: budgetRouter,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded),
		"expected CodeProviderBudgetExceeded, got %s", sigilerr.CodeOf(err))
}

func TestAgentLoop_InvalidModelRefNotMasked(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouterInvalidModelRef{},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	// The error code should be invalid_model_ref, NOT all_unavailable.
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderInvalidModelRef),
		"expected CodeProviderInvalidModelRef, got %s", sigilerr.CodeOf(err))
	assert.False(t, sigilerr.HasCode(err, sigilerr.CodeProviderAllUnavailable),
		"invalid_model_ref should NOT be wrapped as all_unavailable")
}

// ---------------------------------------------------------------------------
// Tool dispatch mock providers
// ---------------------------------------------------------------------------

// mockProviderToolCall emits a tool call on the first Chat() call and
// a text response on subsequent calls. Thread-safe via mutex.
type mockProviderToolCall struct {
	mu       sync.Mutex
	callNum  int
	toolCall *provider.ToolCall
}

func (p *mockProviderToolCall) Name() string                     { return "mock-tool-call" }
func (p *mockProviderToolCall) Available(_ context.Context) bool { return true }
func (p *mockProviderToolCall) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-tool-call"}, nil
}

func (p *mockProviderToolCall) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderToolCall) Close() error { return nil }

func (p *mockProviderToolCall) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 4)
	if call == 0 {
		// First call: emit a tool call event.
		ch <- provider.ChatEvent{
			Type:     provider.EventTypeToolCall,
			ToolCall: p.toolCall,
		}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2},
		}
	} else {
		// Subsequent calls: emit text response.
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Tool result processed."}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 20, OutputTokens: 8},
		}
	}
	close(ch)
	return ch, nil
}

// ---------------------------------------------------------------------------
// Tool dispatch tests
// ---------------------------------------------------------------------------

func TestAgentLoop_ToolCallDispatch(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-1",
			Name:      "get_weather",
			Arguments: `{"city":"London"}`,
		},
	}

	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithResult("sunny, 22C"),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "What is the weather in London?",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// The second LLM call should produce the final text.
	assert.Equal(t, "Tool result processed.", out.Content)
	assert.NotNil(t, out.Usage)
	assert.Equal(t, 20, out.Usage.InputTokens, "usage should come from the final LLM call")

	// Verify the provider was called twice (tool call, then text response).
	toolCallProvider.mu.Lock()
	callCount := toolCallProvider.callNum
	toolCallProvider.mu.Unlock()
	assert.Equal(t, 2, callCount, "provider should be called twice: initial + after tool result")
}

func TestAgentLoop_ToolCallDenied(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-denied",
			Name:      "dangerous_tool",
			Arguments: `{}`,
		},
	}

	// Enforcer that denies all capabilities for "builtin" plugin.
	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet(), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManager(),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "Use the dangerous tool",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err, "denied tool should not fail the entire turn")
	require.NotNil(t, out)

	// The LLM should have received the error as tool result and produced text.
	assert.Equal(t, "Tool result processed.", out.Content)

	// Provider should be called twice: initial (tool call) + re-call with error result.
	toolCallProvider.mu.Lock()
	callCount := toolCallProvider.callNum
	toolCallProvider.mu.Unlock()
	assert.Equal(t, 2, callCount, "provider should be called twice even when tool is denied")
}

func TestAgentLoop_ToolCallNilDispatcher(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Provider that emits a tool call — but with nil ToolDispatcher,
	// the tool calls should be ignored and text returned as-is.
	toolCallProviderWithText := &mockProviderToolCallWithText{
		toolCall: &provider.ToolCall{
			ID:        "tc-ignored",
			Name:      "some_tool",
			Arguments: `{}`,
		},
		textContent: "I wanted to use a tool but will answer directly.",
	}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProviderWithText},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: nil, // explicitly nil
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "Test nil dispatcher",
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	assert.Equal(t, "I wanted to use a tool but will answer directly.", out.Content)
	assert.NotNil(t, out.Usage)

	// Provider should only be called once — no tool loop.
	toolCallProviderWithText.mu.Lock()
	callCount := toolCallProviderWithText.callNum
	toolCallProviderWithText.mu.Unlock()
	assert.Equal(t, 1, callCount, "provider should only be called once when ToolDispatcher is nil")
}

// mockProviderToolCallWithText emits both a tool call and text content
// on the first (and only) call. Used to test nil-dispatcher backward compat.
type mockProviderToolCallWithText struct {
	mu          sync.Mutex
	callNum     int
	toolCall    *provider.ToolCall
	textContent string
}

func (p *mockProviderToolCallWithText) Name() string                     { return "mock-tool-text" }
func (p *mockProviderToolCallWithText) Available(_ context.Context) bool { return true }
func (p *mockProviderToolCallWithText) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-tool-text"}, nil
}

func (p *mockProviderToolCallWithText) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderToolCallWithText) Close() error { return nil }

func (p *mockProviderToolCallWithText) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 4)
	ch <- provider.ChatEvent{
		Type:     provider.EventTypeToolCall,
		ToolCall: p.toolCall,
	}
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: p.textContent}
	ch <- provider.ChatEvent{
		Type:  provider.EventTypeDone,
		Usage: &provider.Usage{InputTokens: 15, OutputTokens: 10},
	}
	close(ch)
	return ch, nil
}

// ---------------------------------------------------------------------------
// Error-propagation mock types
// ---------------------------------------------------------------------------

// mockSessionStoreAppendError wraps mockSessionStore and fails on AppendMessage.
type mockSessionStoreAppendError struct {
	*mockSessionStore
	appendErr error
}

func (m *mockSessionStoreAppendError) AppendMessage(_ context.Context, _ string, _ *store.Message) error {
	return m.appendErr
}

// mockSessionStoreWindowError wraps mockSessionStore and fails on GetActiveWindow.
type mockSessionStoreWindowError struct {
	*mockSessionStore
	windowErr error
}

func (m *mockSessionStoreWindowError) GetActiveWindow(_ context.Context, _ string, _ int) ([]*store.Message, error) {
	return nil, m.windowErr
}

// mockProviderChatError is a provider whose Chat() method returns an error.
type mockProviderChatError struct{}

func (p *mockProviderChatError) Name() string                     { return "mock-chat-error" }
func (p *mockProviderChatError) Available(_ context.Context) bool { return true }
func (p *mockProviderChatError) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-chat-error"}, nil
}

func (p *mockProviderChatError) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderChatError) Close() error { return nil }

func (p *mockProviderChatError) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	return nil, assert.AnError
}

// mockProviderRouterGenericError is a router that returns a generic error (not budget-exceeded).
type mockProviderRouterGenericError struct{}

func (r *mockProviderRouterGenericError) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", assert.AnError
}

func (r *mockProviderRouterGenericError) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	return nil, "", assert.AnError
}

func (r *mockProviderRouterGenericError) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterGenericError) MaxAttempts() int { return 1 }
func (r *mockProviderRouterGenericError) Close() error     { return nil }

// ---------------------------------------------------------------------------
// Budget accounting tests
// ---------------------------------------------------------------------------

func TestAgentLoop_UsageAccountedAfterLLMCall(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Set initial budget with limits.
	session.TokenBudget.MaxPerSession = 100000
	session.TokenBudget.UsedSession = 0
	require.NoError(t, ss.UpdateSession(ctx, session))

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		Enforcer:       newMockEnforcer(),
		ProviderRouter: newMockProviderRouter(), // returns Usage{InputTokens:10, OutputTokens:5}
		AuditStore:     newMockAuditStore(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// Verify token counters were incremented (10 input + 5 output = 15 total).
	updated, err := ss.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, 15, updated.TokenBudget.UsedSession, "UsedSession should be incremented by total tokens")
	assert.Equal(t, 15, updated.TokenBudget.UsedHour, "UsedHour should be incremented by total tokens")
	assert.Equal(t, 15, updated.TokenBudget.UsedDay, "UsedDay should be incremented by total tokens")
}

func TestAgentLoop_UsageAccountedInToolLoop(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	session.TokenBudget.MaxPerSession = 100000
	require.NoError(t, ss.UpdateSession(ctx, session))

	// Tool call provider: first call emits tool call (10+2=12 tokens),
	// second call emits text (20+8=28 tokens). Total = 40.
	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-1",
			Name:      "get_weather",
			Arguments: `{"city":"London"}`,
		},
	}

	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithResult("sunny"),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "weather?",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// Verify cumulative usage: initial call (12) + tool loop re-call (28) = 40.
	updated, err := ss.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, 40, updated.TokenBudget.UsedSession, "UsedSession should accumulate across tool loop iterations")
}

func TestAgentLoop_PartialUsageAccountingSurvivesStreamError(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Set initial budget.
	session.TokenBudget.MaxPerSession = 100000
	session.TokenBudget.UsedSession = 0
	require.NoError(t, ss.UpdateSession(ctx, session))

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		Enforcer:       newMockEnforcer(),
		ProviderRouter: newMockProviderRouterStreamUsageThenError(), // emits text_delta, usage (30+20=50), then error
		AuditStore:     newMockAuditStore(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err, "ProcessMessage should return error when stream emits error event")
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderUpstreamFailure),
		"expected CodeProviderUpstreamFailure, got %s", sigilerr.CodeOf(err))

	// Verify token budget was incremented despite the stream failure.
	// The provider emitted a usage event (30 input + 20 output = 50 tokens) before the error.
	updated, err := ss.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, 50, updated.TokenBudget.UsedSession,
		"UsedSession should be incremented by usage event even when stream fails")
	assert.Equal(t, 50, updated.TokenBudget.UsedHour,
		"UsedHour should be incremented by usage event even when stream fails")
	assert.Equal(t, 50, updated.TokenBudget.UsedDay,
		"UsedDay should be incremented by usage event even when stream fails")
}

// ---------------------------------------------------------------------------
// Failover cap test
// ---------------------------------------------------------------------------

func TestAgentLoop_FailoverCapMatchesRouterChainLength(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Router that returns MaxAttempts=3 but always fails routing.
	router := &mockProviderRouterWithAttempts{maxAttempts: 3}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)

	// The router should have been called exactly maxAttempts times (3).
	assert.Equal(t, 3, router.callCount(), "loop should try exactly MaxAttempts() providers")
}

func TestAgentLoop_FailoverAccumulatesAllProviderFailures(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Router that returns different providers with different failure modes.
	router := &mockProviderRouterMultipleFailures{
		providers: []provider.Provider{
			&mockProviderChatErrorNamed{name: "provider-alpha"},
			&mockProviderEmptyStreamNamed{name: "provider-beta"},
			&mockProviderFirstEventErrorNamed{name: "provider-gamma", errMsg: "rate limit exceeded"},
		},
	}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderAllUnavailable),
		"expected CodeProviderAllUnavailable, got %s", sigilerr.CodeOf(err))

	// Error message should include all provider names and their failures.
	errMsg := err.Error()
	assert.Contains(t, errMsg, "provider-alpha")
	assert.Contains(t, errMsg, "provider-beta")
	assert.Contains(t, errMsg, "provider-gamma")
	assert.Contains(t, errMsg, "rate limit exceeded")
	assert.Contains(t, errMsg, "all providers failed")
}

// mockProviderRouterWithAttempts is a router that tracks RouteWithBudget calls
// and returns a provider that fails on Chat() to trigger retry.
type mockProviderRouterWithAttempts struct {
	maxAttempts int
	mu          sync.Mutex
	calls       int
}

func (r *mockProviderRouterWithAttempts) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return &mockProviderChatError{}, "mock-model", nil
}

func (r *mockProviderRouterWithAttempts) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return &mockProviderChatError{}, "mock-model", nil
}

func (r *mockProviderRouterWithAttempts) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterWithAttempts) MaxAttempts() int { return r.maxAttempts }
func (r *mockProviderRouterWithAttempts) Close() error     { return nil }

func (r *mockProviderRouterWithAttempts) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// mockProviderHealthBase provides common health tracking functionality.
// Embed this in mock providers to track RecordFailure/RecordSuccess calls.
type mockProviderHealthBase struct {
	mu           sync.Mutex
	failureCount int
}

func (p *mockProviderHealthBase) RecordFailure() {
	p.mu.Lock()
	p.failureCount++
	p.mu.Unlock()
}

func (p *mockProviderHealthBase) RecordSuccess() {}

func (p *mockProviderHealthBase) getFailureCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failureCount
}

// mockProviderChatErrorWithHealth is a provider whose Chat() fails and
// implements provider.HealthReporter to track RecordFailure calls.
type mockProviderChatErrorWithHealth struct {
	mockProviderHealthBase
}

func (p *mockProviderChatErrorWithHealth) Name() string                     { return "mock-health-error" }
func (p *mockProviderChatErrorWithHealth) Available(_ context.Context) bool { return true }
func (p *mockProviderChatErrorWithHealth) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-health-error"}, nil
}

func (p *mockProviderChatErrorWithHealth) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderChatErrorWithHealth) Close() error { return nil }
func (p *mockProviderChatErrorWithHealth) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	return nil, assert.AnError
}

func TestAgentLoop_ChatFailureCallsRecordFailure(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	healthProv := &mockProviderChatErrorWithHealth{}
	router := &mockProviderRouter{provider: healthProv}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)

	// RecordFailure should have been called for the pre-stream Chat() error.
	assert.Equal(t, 1, healthProv.getFailureCount(),
		"RecordFailure should be called on pre-stream Chat() error")
}

// mockProviderEmptyStreamWithHealth is a provider whose Chat() returns a channel
// that closes immediately without events, and tracks RecordFailure calls.
type mockProviderEmptyStreamWithHealth struct {
	mockProviderHealthBase
}

func (p *mockProviderEmptyStreamWithHealth) Name() string { return "mock-empty-stream-health" }
func (p *mockProviderEmptyStreamWithHealth) Available(_ context.Context) bool {
	return true
}

func (p *mockProviderEmptyStreamWithHealth) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-empty-stream-health"}, nil
}

func (p *mockProviderEmptyStreamWithHealth) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderEmptyStreamWithHealth) Close() error { return nil }
func (p *mockProviderEmptyStreamWithHealth) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent)
	close(ch) // Close immediately without sending any events
	return ch, nil
}

func TestAgentLoop_EmptyStreamCallsRecordFailure(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	healthProv := &mockProviderEmptyStreamWithHealth{}
	router := &mockProviderRouter{provider: healthProv}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)

	// RecordFailure should have been called for the empty stream.
	assert.Equal(t, 1, healthProv.getFailureCount(),
		"RecordFailure should be called when provider returns empty stream")
}

// mockProviderFirstEventErrorWithHealth is a provider whose Chat() returns a channel
// where the first event is an error, and tracks RecordFailure calls.
type mockProviderFirstEventErrorWithHealth struct {
	mockProviderHealthBase
}

func (p *mockProviderFirstEventErrorWithHealth) Name() string {
	return "mock-first-event-error-health"
}

func (p *mockProviderFirstEventErrorWithHealth) Available(_ context.Context) bool {
	return true
}

func (p *mockProviderFirstEventErrorWithHealth) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-first-event-error-health"}, nil
}

func (p *mockProviderFirstEventErrorWithHealth) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderFirstEventErrorWithHealth) Close() error { return nil }
func (p *mockProviderFirstEventErrorWithHealth) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 1)
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: "first event is error"}
	close(ch)
	return ch, nil
}

func TestAgentLoop_FirstEventErrorCallsRecordFailure(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	healthProv := &mockProviderFirstEventErrorWithHealth{}
	router := &mockProviderRouter{provider: healthProv}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	_, err = loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)

	// RecordFailure should have been called for the first-event error.
	assert.Equal(t, 1, healthProv.getFailureCount(),
		"RecordFailure should be called when first event is an error")
}

// ---------------------------------------------------------------------------
// Tool loop iteration cap tests
// ---------------------------------------------------------------------------

// mockProviderAlwaysToolCall always emits a tool call, simulating a runaway LLM.
type mockProviderAlwaysToolCall struct {
	mu      sync.Mutex
	callNum int
}

func (p *mockProviderAlwaysToolCall) Name() string                     { return "mock-always-tool" }
func (p *mockProviderAlwaysToolCall) Available(_ context.Context) bool { return true }
func (p *mockProviderAlwaysToolCall) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-always-tool"}, nil
}

func (p *mockProviderAlwaysToolCall) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderAlwaysToolCall) Close() error { return nil }

func (p *mockProviderAlwaysToolCall) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{
		Type: provider.EventTypeToolCall,
		ToolCall: &provider.ToolCall{
			ID:        fmt.Sprintf("tc-%d", call),
			Name:      "infinite_tool",
			Arguments: `{}`,
		},
	}
	ch <- provider.ChatEvent{
		Type:  provider.EventTypeDone,
		Usage: &provider.Usage{InputTokens: 5, OutputTokens: 2},
	}
	close(ch)
	return ch, nil
}

func (p *mockProviderAlwaysToolCall) getCallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.callNum
}

func TestAgentLoop_ToolLoopIterationCapEnforced(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	alwaysToolProvider := &mockProviderAlwaysToolCall{}

	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithResult("result"),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: alwaysToolProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "run infinite tools",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopFailure),
		"expected CodeAgentLoopFailure, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "exceeded maximum iterations")

	// The provider should have been called 1 (initial) + 5 (loop iterations) = 6 times.
	assert.Equal(t, 6, alwaysToolProvider.getCallCount(),
		"provider should be called once initially plus maxToolLoopIterations times")
}

func TestAgentLoop_ToolRuntimeFailureRecovery(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Provider that emits a tool call on first Chat() call,
	// then a text response on second call (after receiving the error).
	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-fail",
			Name:      "failing_tool",
			Arguments: `{"input":"test"}`,
		},
	}

	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	// Plugin executor that returns an error simulating a tool crash/timeout.
	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithError(sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "tool crashed")),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "Use the failing tool",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err, "tool runtime failure should not fail the entire turn")
	require.NotNil(t, out)

	// The loop should complete successfully with the LLM's text response.
	assert.Equal(t, "Tool result processed.", out.Content)

	// Provider should have been called twice:
	// 1. Initial call (returns tool call)
	// 2. Re-call with tool error result (returns text response)
	toolCallProvider.mu.Lock()
	callCount := toolCallProvider.callNum
	toolCallProvider.mu.Unlock()
	assert.Equal(t, 2, callCount, "provider should be called twice: initial + after tool error")
}

// ---------------------------------------------------------------------------
// Multi-iteration tool loop provider and test
// ---------------------------------------------------------------------------

// mockProviderMultiToolCall emits tool calls for the first N Chat() calls,
// then a text response. Used to test multi-iteration tool loops.
type mockProviderMultiToolCall struct {
	mu           sync.Mutex
	callNum      int
	toolCallsFor int // number of calls that emit tool calls
}

func (p *mockProviderMultiToolCall) Name() string                     { return "mock-multi-tool" }
func (p *mockProviderMultiToolCall) Available(_ context.Context) bool { return true }
func (p *mockProviderMultiToolCall) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-multi-tool"}, nil
}

func (p *mockProviderMultiToolCall) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderMultiToolCall) Close() error { return nil }

func (p *mockProviderMultiToolCall) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	call := p.callNum
	p.callNum++
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 4)
	if call < p.toolCallsFor {
		// Emit tool call — each iteration uses 10 input + 3 output = 13 tokens
		ch <- provider.ChatEvent{
			Type: provider.EventTypeToolCall,
			ToolCall: &provider.ToolCall{
				ID:        fmt.Sprintf("tc-%d", call),
				Name:      "multi_tool",
				Arguments: `{}`,
			},
		}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 10, OutputTokens: 3},
		}
	} else {
		// Final call: emit text — uses 20 input + 7 output = 27 tokens
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Multi-tool done."}
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeDone,
			Usage: &provider.Usage{InputTokens: 20, OutputTokens: 7},
		}
	}
	close(ch)
	return ch, nil
}

func TestAgentLoop_BudgetCumulativeAcrossMultipleToolIterations(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	session.TokenBudget.MaxPerSession = 100000
	require.NoError(t, ss.UpdateSession(ctx, session))

	// Provider emits tool calls for first 3 calls (initial + 2 loop iterations),
	// then text on the 4th call (3rd loop iteration resolves).
	// Call 0 (initial): 13 tokens (tool call)
	// Call 1 (loop iter 1): 13 tokens (tool call)
	// Call 2 (loop iter 2): 13 tokens (tool call)
	// Call 3 (loop iter 3): 27 tokens (text response)
	// Total: 13 + 13 + 13 + 27 = 66 tokens
	multiToolProvider := &mockProviderMultiToolCall{toolCallsFor: 3}

	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithResult("ok"),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: multiToolProvider},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
		ToolDispatcher: dispatcher,
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "use tools multiple times",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	assert.Equal(t, "Multi-tool done.", out.Content)

	// Verify cumulative session budget: all 4 LLM calls accounted.
	// Call 1 (initial): 13 tokens
	// Call 2 (tool loop iteration 1): 13 tokens
	// Call 3 (tool loop iteration 2): 13 tokens
	// Call 4 (tool loop iteration 3, final): 27 tokens
	// Total: 13 + 13 + 13 + 27 = 66.
	updated, err := ss.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, 66, updated.TokenBudget.UsedSession,
		"UsedSession should accumulate across ALL tool loop iterations, not just the final one")

	// Returned usage reflects only the final LLM call (current behavior).
	assert.Equal(t, 20, out.Usage.InputTokens, "returned usage should be from final LLM call")
	assert.Equal(t, 7, out.Usage.OutputTokens, "returned usage should be from final LLM call")
}

// ---------------------------------------------------------------------------
// Context cancellation test
// ---------------------------------------------------------------------------

// mockProviderBlocking blocks on Chat() until context is cancelled, then
// emits an error event to signal the cancellation.
type mockProviderBlocking struct {
	mu       sync.Mutex
	chatCall chan struct{}
}

func (p *mockProviderBlocking) Name() string                     { return "mock-blocking" }
func (p *mockProviderBlocking) Available(_ context.Context) bool { return true }
func (p *mockProviderBlocking) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-blocking"}, nil
}

func (p *mockProviderBlocking) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}
func (p *mockProviderBlocking) Close() error { return nil }

func (p *mockProviderBlocking) Chat(ctx context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	p.mu.Lock()
	p.chatCall <- struct{}{} // signal that Chat was called
	p.mu.Unlock()

	ch := make(chan provider.ChatEvent, 2)
	go func() {
		defer close(ch)
		// Emit first event so failover doesn't kick in
		ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Starting..."}
		// Block until context is cancelled
		<-ctx.Done()
		// Emit error event after cancellation
		ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: ctx.Err().Error()}
	}()
	return ch, nil
}

func TestAgentLoop_ContextCancellation(t *testing.T) {
	sm := newMockSessionManager()
	bgCtx := context.Background()

	session, err := sm.Create(bgCtx, "ws-1", "user-1")
	require.NoError(t, err)

	blockingProv := &mockProviderBlocking{
		chatCall: make(chan struct{}, 1),
	}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: blockingProv},
		AuditStore:     newMockAuditStore(),
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(bgCtx)
	defer cancel()

	// Run ProcessMessage in a goroutine
	errCh := make(chan error, 1)
	resultCh := make(chan *agent.OutboundMessage, 1)
	go func() {
		out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
			SessionID:   session.ID,
			WorkspaceID: "ws-1",
			UserID:      "user-1",
			Content:     "test cancellation",
		})
		resultCh <- out
		errCh <- err
	}()

	// Wait for Chat to be called
	select {
	case <-blockingProv.chatCall:
		// Chat was called, now cancel the context
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Chat to be called")
	}

	// Cancel the context
	cancel()

	// Wait for ProcessMessage to return with an error
	select {
	case err := <-errCh:
		out := <-resultCh
		require.Error(t, err, "ProcessMessage should return error when context is cancelled")
		assert.Nil(t, out, "out should be nil when error occurs")
		// Verify the operation terminated promptly after cancellation
		// (reaching this point means it didn't hang)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ProcessMessage to terminate after context cancellation")
	}
}

func TestAgentLoop_AuditFailureDoesNotFailTurn(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	// Audit store that always returns an error.
	failingAuditStore := &mockAuditStoreError{err: assert.AnError}

	loop, err := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     failingAuditStore,
		Enforcer:       newMockEnforcer(),
	})
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   session.ID,
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "test audit failure",
	})

	// ProcessMessage should succeed despite audit failure (best-effort semantics).
	require.NoError(t, err, "ProcessMessage should succeed even when audit logging fails")
	require.NotNil(t, out)
	assert.Equal(t, session.ID, out.SessionID)
	assert.Contains(t, out.Content, "Hello, world!")

	// Verify audit was attempted.
	assert.Equal(t, int32(1), failingAuditStore.appendCount.Load(), "audit append should have been attempted")
}

func TestAgentLoop_AuditStoreConsecutiveFailures(t *testing.T) {
	sm := newMockSessionManager()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	tests := []struct {
		name                    string
		failuresBeforeSuccess   int
		wantFinalFailCount      int64
		wantSuccessfulResponses int
	}{
		{
			name:                    "consecutive failures increment counter",
			failuresBeforeSuccess:   3,
			wantFinalFailCount:      3,
			wantSuccessfulResponses: 3,
		},
		{
			name:                    "success resets counter to zero",
			failuresBeforeSuccess:   0,
			wantFinalFailCount:      0,
			wantSuccessfulResponses: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create an audit store that fails for N messages, then succeeds.
			auditStore := &mockAuditStoreConditional{
				failUntilCallCount: tt.failuresBeforeSuccess,
			}

			loop, err := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     auditStore,
				Enforcer:       newMockEnforcer(),
			})
			require.NoError(t, err)

			// Process N failing messages (if configured).
			for i := 0; i < tt.failuresBeforeSuccess; i++ {
				out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
					SessionID:   session.ID,
					WorkspaceID: "ws-1",
					UserID:      "user-1",
					Content:     fmt.Sprintf("message %d", i+1),
				})

				// Each message should succeed despite audit failure.
				require.NoError(t, err, "message %d: ProcessMessage should succeed even when audit fails", i+1)
				require.NotNil(t, out)
				assert.Equal(t, session.ID, out.SessionID)

				// Verify consecutive failure count increments.
				expectedFailCount := int64(i + 1)
				actualFailCount := loop.AuditFailCount()
				assert.Equal(t, expectedFailCount, actualFailCount,
					"after message %d: auditFailCount should be %d", i+1, expectedFailCount)
			}

			// If test includes a success case, process one more message.
			if tt.failuresBeforeSuccess == 0 || tt.name == "success resets counter to zero" {
				// For the reset test, we need to fail first, then succeed.
				if tt.name == "success resets counter to zero" {
					// First, cause 2 failures.
					auditStore.failUntilCallCount = 2
					for i := 0; i < 2; i++ {
						out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
							SessionID:   session.ID,
							WorkspaceID: "ws-1",
							UserID:      "user-1",
							Content:     fmt.Sprintf("fail message %d", i+1),
						})
						require.NoError(t, err)
						require.NotNil(t, out)
					}
					assert.Equal(t, int64(2), loop.AuditFailCount(), "should have 2 consecutive failures")

					// Now allow success (set failUntilCallCount to current count so next call succeeds).
					auditStore.failUntilCallCount = int(auditStore.callCount.Load())
				}

				// Process a message that will succeed in audit.
				out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
					SessionID:   session.ID,
					WorkspaceID: "ws-1",
					UserID:      "user-1",
					Content:     "success message",
				})
				require.NoError(t, err)
				require.NotNil(t, out)

				// Counter should reset to 0 after successful audit.
				assert.Equal(t, int64(0), loop.AuditFailCount(),
					"auditFailCount should reset to 0 after successful audit append")
			}

			// Verify final state.
			assert.Equal(t, tt.wantFinalFailCount, loop.AuditFailCount(),
				"final auditFailCount should be %d", tt.wantFinalFailCount)
		})
	}
}

// ---------------------------------------------------------------------------
// Provider mid-stream failure and health tracking tests
// ---------------------------------------------------------------------------

// mockProviderMidStreamFailureWithHealth is a provider that:
// 1. Emits a successful first event (to pass failover checks)
// 2. Emits additional text events
// 3. Emits an error event mid-stream
// 4. Tracks RecordFailure calls for health verification
type mockProviderMidStreamFailureWithHealth struct {
	mockProviderHealthBase
}

func (p *mockProviderMidStreamFailureWithHealth) Name() string {
	return "mock-mid-stream-failure-health"
}

func (p *mockProviderMidStreamFailureWithHealth) Available(_ context.Context) bool {
	return true
}

func (p *mockProviderMidStreamFailureWithHealth) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: "mock-mid-stream-failure-health"}, nil
}

func (p *mockProviderMidStreamFailureWithHealth) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderMidStreamFailureWithHealth) Close() error { return nil }

func (p *mockProviderMidStreamFailureWithHealth) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 5)
	// First event: successful text delta (passes failover check)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "Starting response..."}
	// Second event: more text
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "processing..."}
	// Third event: usage update
	ch <- provider.ChatEvent{Type: provider.EventTypeUsage, Usage: &provider.Usage{InputTokens: 25, OutputTokens: 15}}
	// Fourth event: mid-stream failure
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: "connection dropped mid-stream"}
	close(ch)
	return ch, nil
}

func TestAgentLoop_MidStreamFailureCallsRecordFailure(t *testing.T) {
	tests := []struct {
		name                 string
		successfulFirstEvent bool
		wantError            bool
		wantRecordFailure    bool
		wantUsageAccounted   bool
	}{
		{
			name:                 "mid-stream failure after successful first event",
			successfulFirstEvent: true,
			wantError:            true,
			wantRecordFailure:    true, // Mid-stream failures DO call RecordFailure for health tracking
			wantUsageAccounted:   true, // Usage emitted before error should be accounted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, ss := newMockSessionManagerWithStore()
			ctx := context.Background()

			session, err := sm.Create(ctx, "ws-1", "user-1")
			require.NoError(t, err)

			// Set initial budget to track usage accounting.
			session.TokenBudget.MaxPerSession = 100000
			session.TokenBudget.UsedSession = 0
			require.NoError(t, ss.UpdateSession(ctx, session))

			healthProv := &mockProviderMidStreamFailureWithHealth{}
			router := &mockProviderRouter{provider: healthProv}

			loop, err := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: router,
				AuditStore:     newMockAuditStore(),
				Enforcer:       newMockEnforcer(),
			})
			require.NoError(t, err)

			out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
				SessionID:   session.ID,
				WorkspaceID: "ws-1",
				UserID:      "user-1",
				Content:     "test mid-stream failure",
			})

			if tt.wantError {
				require.Error(t, err, "ProcessMessage should return error on mid-stream failure")
				assert.Nil(t, out)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderUpstreamFailure),
					"expected CodeProviderUpstreamFailure, got %s", sigilerr.CodeOf(err))
				assert.Contains(t, err.Error(), "connection dropped mid-stream")
			} else {
				require.NoError(t, err)
				require.NotNil(t, out)
			}

			// Verify RecordFailure behavior.
			// According to design decision D036 (docs/decisions/decision-log.md),
			// mid-stream failures do not trigger failover (complexity of buffering and replay),
			// but they DO call RecordFailure to enable health tracking. This allows the
			// circuit breaker to respond to persistent mid-stream failures (connection drops,
			// malformed responses) even though failover doesn't happen for those errors.
			failureCount := healthProv.getFailureCount()
			if tt.wantRecordFailure {
				assert.Equal(t, 1, failureCount,
					"RecordFailure should be called for mid-stream failure")
			} else {
				assert.Equal(t, 0, failureCount,
					"RecordFailure should NOT be called for mid-stream failure (per D036)")
			}

			// Verify usage accounting — tokens consumed before the error should be accounted.
			if tt.wantUsageAccounted {
				updated, err := ss.GetSession(ctx, session.ID)
				require.NoError(t, err)
				// Provider emitted Usage{InputTokens: 25, OutputTokens: 15} before the error.
				expectedUsage := 25 + 15 // 40 tokens
				assert.Equal(t, expectedUsage, updated.TokenBudget.UsedSession,
					"UsedSession should be incremented by usage emitted before mid-stream failure")
				assert.Equal(t, expectedUsage, updated.TokenBudget.UsedHour,
					"UsedHour should be incremented by usage emitted before mid-stream failure")
				assert.Equal(t, expectedUsage, updated.TokenBudget.UsedDay,
					"UsedDay should be incremented by usage emitted before mid-stream failure")
			}

			// Verify no assistant message was persisted (partial text discarded on stream error).
			history, err := ss.GetActiveWindow(ctx, session.ID, 10)
			require.NoError(t, err)
			for _, msg := range history {
				assert.NotEqual(t, "assistant", msg.Role,
					"assistant message should not be persisted after mid-stream error")
			}
		})
	}
}

func TestNewLoop_ValidatesDependencies(t *testing.T) {
	tests := []struct {
		name    string
		cfg     agent.LoopConfig
		wantErr bool
		wantMsg string
	}{
		{
			name: "missing SessionManager",
			cfg: agent.LoopConfig{
				Enforcer:       &security.Enforcer{},
				ProviderRouter: newMockProviderRouter(),
			},
			wantErr: true,
			wantMsg: "SessionManager is required",
		},
		{
			name: "missing Enforcer",
			cfg: agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				ProviderRouter: newMockProviderRouter(),
			},
			wantErr: true,
			wantMsg: "Enforcer is required",
		},
		{
			name: "missing ProviderRouter",
			cfg: agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				Enforcer:       &security.Enforcer{},
			},
			wantErr: true,
			wantMsg: "ProviderRouter is required",
		},
		{
			name: "all required dependencies present",
			cfg: agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				Enforcer:       &security.Enforcer{},
				ProviderRouter: newMockProviderRouter(),
			},
			wantErr: false,
		},
		{
			name: "optional dependencies can be nil",
			cfg: agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				Enforcer:       &security.Enforcer{},
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     nil,
				ToolDispatcher: nil,
				ToolRegistry:   nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loop, err := agent.NewLoop(tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, loop)
				assert.Contains(t, err.Error(), tt.wantMsg)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopInvalidInput))
			} else {
				require.NoError(t, err)
				assert.NotNil(t, loop)
			}
		})
	}
}

// mockProviderRouterMultipleFailures is a router that returns different providers
// in sequence, all of which fail in different ways.
type mockProviderRouterMultipleFailures struct {
	providers []provider.Provider
	mu        sync.Mutex
	callIndex int
}

func (r *mockProviderRouterMultipleFailures) Route(_ context.Context, _, _ string) (provider.Provider, string, error) {
	return nil, "", assert.AnError
}

func (r *mockProviderRouterMultipleFailures) RouteWithBudget(_ context.Context, _, _ string, _ *provider.Budget, _ []string) (provider.Provider, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.callIndex >= len(r.providers) {
		return nil, "", assert.AnError
	}

	prov := r.providers[r.callIndex]
	r.callIndex++
	return prov, "mock-model", nil
}

func (r *mockProviderRouterMultipleFailures) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterMultipleFailures) MaxAttempts() int {
	return len(r.providers)
}

func (r *mockProviderRouterMultipleFailures) Close() error {
	return nil
}

// mockProviderChatErrorNamed is a provider whose Chat() fails with a named provider.
type mockProviderChatErrorNamed struct {
	name string
}

func (p *mockProviderChatErrorNamed) Name() string                     { return p.name }
func (p *mockProviderChatErrorNamed) Available(_ context.Context) bool { return true }
func (p *mockProviderChatErrorNamed) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: p.name}, nil
}

func (p *mockProviderChatErrorNamed) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderChatErrorNamed) Close() error { return nil }

func (p *mockProviderChatErrorNamed) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	return nil, fmt.Errorf("chat failed")
}

// mockProviderEmptyStreamNamed is a provider whose Chat() returns a channel that closes immediately.
type mockProviderEmptyStreamNamed struct {
	name string
}

func (p *mockProviderEmptyStreamNamed) Name() string                     { return p.name }
func (p *mockProviderEmptyStreamNamed) Available(_ context.Context) bool { return true }
func (p *mockProviderEmptyStreamNamed) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: p.name}, nil
}

func (p *mockProviderEmptyStreamNamed) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderEmptyStreamNamed) Close() error { return nil }

func (p *mockProviderEmptyStreamNamed) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent)
	close(ch)
	return ch, nil
}

// mockProviderFirstEventErrorNamed is a provider whose first event is an error.
type mockProviderFirstEventErrorNamed struct {
	name   string
	errMsg string
}

func (p *mockProviderFirstEventErrorNamed) Name() string                     { return p.name }
func (p *mockProviderFirstEventErrorNamed) Available(_ context.Context) bool { return true }
func (p *mockProviderFirstEventErrorNamed) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: true, Provider: p.name}, nil
}

func (p *mockProviderFirstEventErrorNamed) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (p *mockProviderFirstEventErrorNamed) Close() error { return nil }

func (p *mockProviderFirstEventErrorNamed) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 1)
	ch <- provider.ChatEvent{Type: provider.EventTypeError, Error: p.errMsg}
	close(ch)
	return ch, nil
}

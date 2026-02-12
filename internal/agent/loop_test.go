// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
		Hooks: &agent.LoopHooks{
			OnReceive: record("receive"),
			OnPrepare: record("prepare"),
			OnCallLLM: record("call_llm"),
			OnProcess: record("process"),
			OnRespond: record("respond"),
			OnAudit:   record("audit"),
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

			loop := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
			})

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

			loop := agent.NewLoop(agent.LoopConfig{
				SessionManager: sm,
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
			})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
	})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterWithBudgetExceeded(),
		AuditStore:     newMockAuditStore(),
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

func TestAgentLoop_ProviderStreamErrorOnly(t *testing.T) {
	sm, ss := newMockSessionManagerWithStore()
	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterStreamError(),
		AuditStore:     newMockAuditStore(),
	})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterStreamPartialThenError(),
		AuditStore:     newMockAuditStore(),
	})

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
	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouterCapturing(capturer),
		AuditStore:     newMockAuditStore(),
	})

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

	// Verify message order: system → user.
	assert.Equal(t, store.MessageRoleSystem, messages[0].Role, "first message should be system prompt")
	assert.Equal(t, store.MessageRoleUser, messages[1].Role, "second message should be user message")
	assert.Equal(t, "test message", messages[1].Content, "user message content should match")
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
			loop := agent.NewLoop(agent.LoopConfig{
				SessionManager: newMockSessionManager(),
				ProviderRouter: newMockProviderRouter(),
				AuditStore:     newMockAuditStore(),
			})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
	})

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:   "nonexistent-session",
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	})
	require.Error(t, err)
	assert.Nil(t, out)
	// The error should be a not-found error from the session store.
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopFailure),
		"expected wrapped error code, got %s", sigilerr.CodeOf(err))
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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
	})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: newMockProviderRouter(),
		AuditStore:     newMockAuditStore(),
	})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
	})

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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: router,
		AuditStore:     newMockAuditStore(),
	})

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
	assert.Contains(t, err.Error(), "routing provider")
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
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool:*"), security.NewCapabilitySet())

	dispatcher := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManagerWithResult("sunny, 22C"),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		ToolDispatcher: dispatcher,
	})

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "What is the weather in London?",
		WorkspaceAllow:  security.NewCapabilitySet("tool:*"),
		UserPermissions: security.NewCapabilitySet("tool:*"),
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

	dispatcher := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  newMockPluginManager(),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProvider},
		AuditStore:     newMockAuditStore(),
		ToolDispatcher: dispatcher,
	})

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "Use the dangerous tool",
		WorkspaceAllow:  security.NewCapabilitySet("tool:*"),
		UserPermissions: security.NewCapabilitySet("tool:*"),
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

	loop := agent.NewLoop(agent.LoopConfig{
		SessionManager: sm,
		ProviderRouter: &mockProviderRouter{provider: toolCallProviderWithText},
		AuditStore:     newMockAuditStore(),
		ToolDispatcher: nil, // explicitly nil
	})

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

func (r *mockProviderRouterGenericError) RegisterProvider(_ string, _ provider.Provider) error {
	return nil
}

func (r *mockProviderRouterGenericError) Close() error { return nil }

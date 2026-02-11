// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
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

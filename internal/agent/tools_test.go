// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wildcardCaps returns a CapabilitySet that allows everything.
func wildcardCaps() security.CapabilitySet {
	return security.NewCapabilitySet("*")
}

func TestToolDispatcher_AllowedTool(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{"query":"test"}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "executed", result.Content)
}

func TestToolDispatcher_DeniedCapability(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcerDenyAll(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{"query":"test"}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "denied")
}

func TestToolDispatcher_Timeout(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       newMockEnforcer(),
		PluginManager:  newMockPluginManagerSlow(5 * time.Second),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "slow-tool",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.True(t,
		sigilerr.HasCode(err, sigilerr.CodeAgentToolTimeout) ||
			assert.ObjectsAreEqual(context.DeadlineExceeded, err),
		"expected timeout or deadline exceeded error, got: %v", err,
	)
}

func TestToolDispatcher_ToolBudgetExceeded(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	req := agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		TurnID:          "turn-1",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	}

	const maxCalls = 20

	// Execute maxCalls times — all should succeed.
	for i := range maxCalls {
		result, err := d.ExecuteForTurn(ctx, req, maxCalls)
		require.NoError(t, err, "call %d should succeed", i+1)
		require.NotNil(t, result)
	}

	// The next call should be denied by the budget.
	result, err := d.ExecuteForTurn(ctx, req, maxCalls)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "budget")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentToolBudgetExceeded))
}

func TestToolDispatcher_BudgetPerTurnIsolation(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	const maxCalls = 5

	// Create request for turn-1.
	reqTurn1 := agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		TurnID:          "turn-1",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	}

	// Exhaust budget on turn-1.
	for i := 0; i < maxCalls; i++ {
		result, err := d.ExecuteForTurn(ctx, reqTurn1, maxCalls)
		require.NoError(t, err, "turn-1 call %d should succeed", i+1)
		require.NotNil(t, result)
	}

	// Next call on turn-1 should fail.
	result, err := d.ExecuteForTurn(ctx, reqTurn1, maxCalls)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentToolBudgetExceeded))

	// Create request for turn-2 with same session/workspace.
	reqTurn2 := agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1", // Same session
		WorkspaceID:     "ws-1",   // Same workspace
		PluginName:      "test-plugin",
		TurnID:          "turn-2", // Different turn
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	}

	// Turn-2 should have independent budget — all calls should succeed.
	for i := 0; i < maxCalls; i++ {
		result, err := d.ExecuteForTurn(ctx, reqTurn2, maxCalls)
		require.NoError(t, err, "turn-2 call %d should succeed", i+1)
		require.NotNil(t, result)
	}

	// Next call on turn-2 should fail.
	result, err = d.ExecuteForTurn(ctx, reqTurn2, maxCalls)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentToolBudgetExceeded))
}

func TestToolDispatcher_ConcurrentMultiTurnBudget(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	const maxCalls = 10
	const numTurns = 5

	var wg sync.WaitGroup
	errors := make(chan error, numTurns*maxCalls)

	// Launch concurrent turns.
	for turnNum := 0; turnNum < numTurns; turnNum++ {
		wg.Add(1)
		go func(turnID int) {
			defer wg.Done()

			req := agent.ToolCallRequest{
				ToolName:        "search",
				Arguments:       `{}`,
				SessionID:       fmt.Sprintf("sess-%d", turnID),
				WorkspaceID:     "ws-1",
				PluginName:      "test-plugin",
				TurnID:          fmt.Sprintf("turn-%d", turnID),
				WorkspaceAllow:  wildcardCaps(),
				UserPermissions: wildcardCaps(),
			}

			// Execute maxCalls times for this turn.
			for i := 0; i < maxCalls; i++ {
				_, err := d.ExecuteForTurn(ctx, req, maxCalls)
				if err != nil {
					errors <- fmt.Errorf("turn-%d call %d failed: %w", turnID, i+1, err)
					return
				}
			}

			// The next call should fail due to budget.
			_, err := d.ExecuteForTurn(ctx, req, maxCalls)
			if err == nil {
				errors <- fmt.Errorf("turn-%d: expected budget exceeded error", turnID)
			} else if !sigilerr.HasCode(err, sigilerr.CodeAgentToolBudgetExceeded) {
				errors <- fmt.Errorf("turn-%d: wrong error code: %w", turnID, err)
			}
		}(turnNum)
	}

	wg.Wait()
	close(errors)

	// Check for any errors.
	for err := range errors {
		t.Error(err)
	}
}

func TestToolDispatcher_ClearTurn(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	const maxCalls = 3

	req := agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		TurnID:          "turn-1",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	}

	var result *agent.ToolResult
	var execErr error

	// Exhaust budget.
	for i := 0; i < maxCalls; i++ {
		result, execErr = d.ExecuteForTurn(ctx, req, maxCalls)
		require.NoError(t, execErr, "call %d should succeed", i+1)
		require.NotNil(t, result)
	}

	// Next call should fail.
	result, execErr = d.ExecuteForTurn(ctx, req, maxCalls)
	require.Error(t, execErr)
	assert.Nil(t, result)
	assert.True(t, sigilerr.HasCode(execErr, sigilerr.CodeAgentToolBudgetExceeded))

	// Clear the turn budget.
	d.ClearTurn("turn-1")

	// Same turn ID should now have a fresh budget.
	for i := 0; i < maxCalls; i++ {
		result, execErr = d.ExecuteForTurn(ctx, req, maxCalls)
		require.NoError(t, execErr, "call %d after clear should succeed", i+1)
		require.NotNil(t, result)
	}

	// Next call should fail again.
	result, execErr = d.ExecuteForTurn(ctx, req, maxCalls)
	require.Error(t, execErr)
	assert.Nil(t, result)
	assert.True(t, sigilerr.HasCode(execErr, sigilerr.CodeAgentToolBudgetExceeded))
}

func TestToolDispatcher_EmptyTurnIDRejected(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx := context.Background()

	req := agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		TurnID:          "", // Empty TurnID
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	}

	result, err := d.ExecuteForTurn(ctx, req, 10)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "TurnID is required")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopInvalidInput))
}

func TestToolDispatcher_NilEnforcerRejected(t *testing.T) {
	_, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      nil, // Nil enforcer should be rejected
		PluginManager: newMockPluginManager(),
		AuditStore:    newMockAuditStore(),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Enforcer is required")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopInvalidInput))
}

func TestToolDispatcher_NilPluginManagerRejected(t *testing.T) {
	_, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: nil, // Nil plugin manager should be rejected
		AuditStore:    newMockAuditStore(),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "PluginManager is required")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopInvalidInput))
}

func TestToolDispatcher_WorkspaceUserCapabilityIntersection(t *testing.T) {
	tests := []struct {
		name            string
		pluginAllow     []string // plugin capability patterns
		workspaceAllow  []string // workspace allowlist patterns
		userPermissions []string // user permission patterns
		toolName        string
		wantErr         bool
		wantReason      string // substring expected in error message
	}{
		{
			name:            "all allow wildcard",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"*"},
			userPermissions: []string{"*"},
			toolName:        "search",
			wantErr:         false,
		},
		{
			name:            "exact match all three",
			pluginAllow:     []string{"tool.search"},
			workspaceAllow:  []string{"tool.search"},
			userPermissions: []string{"tool.search"},
			toolName:        "search",
			wantErr:         false,
		},
		{
			name:            "denied by workspace empty set",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{},
			userPermissions: []string{"*"},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "workspace_allow_missing",
		},
		{
			name:            "denied by workspace wrong capability",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.read"},
			userPermissions: []string{"*"},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "workspace_allow_missing",
		},
		{
			name:            "denied by user empty set",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"*"},
			userPermissions: []string{},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "user_permission_missing",
		},
		{
			name:            "denied by user wrong capability",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"*"},
			userPermissions: []string{"tool.read"},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "user_permission_missing",
		},
		{
			name:            "denied by both workspace and user",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{},
			userPermissions: []string{},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "workspace_allow_missing",
		},
		{
			name:            "denied by plugin no capability",
			pluginAllow:     []string{},
			workspaceAllow:  []string{"*"},
			userPermissions: []string{"*"},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "plugin_allow_missing",
		},
		{
			name:            "workspace allows subset user allows all",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.search", "tool.read"},
			userPermissions: []string{"*"},
			toolName:        "search",
			wantErr:         false,
		},
		{
			name:            "workspace allows subset user allows subset matching",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.search", "tool.read"},
			userPermissions: []string{"tool.search"},
			toolName:        "search",
			wantErr:         false,
		},
		{
			name:            "workspace allows subset user allows subset non-matching",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.search", "tool.read"},
			userPermissions: []string{"tool.write"},
			toolName:        "search",
			wantErr:         true,
			wantReason:      "user_permission_missing",
		},
		{
			name:            "glob workspace pattern matches",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.*"},
			userPermissions: []string{"tool.search"},
			toolName:        "search",
			wantErr:         false,
		},
		{
			name:            "glob user pattern matches",
			pluginAllow:     []string{"tool.*"},
			workspaceAllow:  []string{"tool.search"},
			userPermissions: []string{"tool.*"},
			toolName:        "search",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer := security.NewEnforcer(nil)
			enforcer.RegisterPlugin(
				"test-plugin",
				security.NewCapabilitySet(tt.pluginAllow...),
				security.NewCapabilitySet(), // no deny list
			)

			d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
				Enforcer:      enforcer,
				PluginManager: newMockPluginManager(),
				AuditStore:    newMockAuditStore(),
			})
			require.NoError(t, err)

			result, err := d.Execute(context.Background(), agent.ToolCallRequest{
				ToolName:        tt.toolName,
				Arguments:       `{}`,
				SessionID:       "sess-1",
				WorkspaceID:     "ws-1",
				PluginName:      "test-plugin",
				WorkspaceAllow:  security.NewCapabilitySet(tt.workspaceAllow...),
				UserPermissions: security.NewCapabilitySet(tt.userPermissions...),
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied),
					"expected CodePluginCapabilityDenied, got: %v", err)
				assert.Contains(t, err.Error(), tt.wantReason)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, "executed", result.Content)
			}
		})
	}
}

func TestToolDispatcher_DenyShortCircuitsPluginExecution(t *testing.T) {
	mockPluginExec := &mockPluginExecutorTracking{}

	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcerDenyAll(),
		PluginManager: mockPluginExec,
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "denied")
	assert.Equal(t, int32(0), mockPluginExec.callCount.Load(), "plugin executor should not be called when capability is denied")
}

func TestToolDispatcher_PluginRuntimeError(t *testing.T) {
	pluginErr := fmt.Errorf("plugin crashed unexpectedly")
	mockPluginExec := &mockPluginExecutorError{err: pluginErr}

	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: mockPluginExec,
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeCallFailure), "expected CodePluginRuntimeCallFailure")
	assert.Contains(t, err.Error(), "test-plugin")
	assert.Contains(t, err.Error(), "search")
}

func TestToolDispatcher_ContextCancellation(t *testing.T) {
	mockPluginExec := &mockPluginExecutorCtxAware{}

	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: mockPluginExec,
		AuditStore:    newMockAuditStore(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := d.Execute(ctx, agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, context.Canceled, "expected context.Canceled error")
}

func TestToolDispatcher_TimeoutVsCancellation(t *testing.T) {
	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       newMockEnforcer(),
		PluginManager:  newMockPluginManagerSlow(5 * time.Second),
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 1 * time.Second,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after a short delay (before timeout)
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	result, err := d.Execute(ctx, agent.ToolCallRequest{
		ToolName:        "slow-tool",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	// Verify it's a cancellation error, not a timeout error
	assert.ErrorIs(t, err, context.Canceled, "expected context.Canceled, not timeout")
}

// TestToolDispatcher_AuditCalledOnDeny verifies that an audit entry with
// result="denied" is written when the capability enforcer blocks a tool call
// (sigil-7g5.343). Security teams need visibility into capability probing even
// when the call is blocked before execution.
func TestToolDispatcher_AuditCalledOnDeny(t *testing.T) {
	auditStore := newMockAuditStore()

	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcerDenyAll(),
		PluginManager: newMockPluginManager(),
		AuditStore:    auditStore,
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{"q":"test"}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	require.Error(t, err)
	assert.Nil(t, result)

	auditStore.mu.Lock()
	defer auditStore.mu.Unlock()
	require.Len(t, auditStore.entries, 1, "one audit entry must be created when capability is denied")
	entry := auditStore.entries[0]
	assert.Equal(t, "denied", entry.Result, "audit result must be 'denied'")
	assert.Equal(t, "tool_dispatch", entry.Action)
	// Verify arguments are captured in the audit entry.
	args, ok := entry.Details["tool_arguments"]
	assert.True(t, ok, "audit entry must include tool_arguments")
	assert.Equal(t, `{"q":"test"}`, args, "tool_arguments should match the request")
}

func TestToolDispatcher_AuditFailureDoesNotFailExecution(t *testing.T) {
	// Audit store that always returns an error.
	failingAuditStore := &mockAuditStoreError{err: assert.AnError}

	d, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:      newMockEnforcer(),
		PluginManager: newMockPluginManager(),
		AuditStore:    failingAuditStore,
	})
	require.NoError(t, err)

	result, err := d.Execute(context.Background(), agent.ToolCallRequest{
		ToolName:        "search",
		Arguments:       `{}`,
		SessionID:       "sess-1",
		WorkspaceID:     "ws-1",
		PluginName:      "test-plugin",
		WorkspaceAllow:  wildcardCaps(),
		UserPermissions: wildcardCaps(),
	})

	// Tool execution should succeed despite audit failure (best-effort semantics).
	require.NoError(t, err, "tool execution should succeed even when audit logging fails")
	require.NotNil(t, result)
	assert.Equal(t, "executed", result.Content)

	// Verify audit was attempted.
	assert.Equal(t, int32(1), failingAuditStore.appendCount.Load(), "audit append should have been attempted")
}

// ---------------------------------------------------------------------------
// ToolRegistry tests
// ---------------------------------------------------------------------------

func TestToolRegistry_LookupPlugin(t *testing.T) {
	tests := []struct {
		name          string
		registrations map[string]string // toolName → pluginName
		lookupTool    string
		wantPlugin    string
		wantOK        bool
	}{
		{
			name:          "registered tool returns plugin name",
			registrations: map[string]string{"search": "search-plugin"},
			lookupTool:    "search",
			wantPlugin:    "search-plugin",
			wantOK:        true,
		},
		{
			name:          "unregistered tool returns false",
			registrations: map[string]string{"search": "search-plugin"},
			lookupTool:    "unknown-tool",
			wantPlugin:    "",
			wantOK:        false,
		},
		{
			name:          "empty registry returns false",
			registrations: map[string]string{},
			lookupTool:    "search",
			wantPlugin:    "",
			wantOK:        false,
		},
		{
			name: "multiple registrations returns correct plugin",
			registrations: map[string]string{
				"search":      "search-plugin",
				"get_weather": "weather-plugin",
				"calc":        "builtin",
			},
			lookupTool: "get_weather",
			wantPlugin: "weather-plugin",
			wantOK:     true,
		},
		{
			name:          "builtin tool returns builtin",
			registrations: map[string]string{"calc": "builtin"},
			lookupTool:    "calc",
			wantPlugin:    "builtin",
			wantOK:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := agent.NewToolRegistry()
			for tool, plugin := range tt.registrations {
				reg.Register(tool, plugin, provider.ToolDefinition{Name: tool})
			}

			gotPlugin, gotOK := reg.LookupPlugin(tt.lookupTool)
			assert.Equal(t, tt.wantPlugin, gotPlugin)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

func TestToolDispatcher_ResolvesPluginFromRegistry(t *testing.T) {
	// Register "get_weather" under "weather-plugin".
	registry := agent.NewToolRegistry()
	registry.Register("get_weather", "weather-plugin", provider.ToolDefinition{Name: "get_weather"})

	// Create a capturing plugin executor that records the plugin name.
	capturer := &mockPluginExecutorCapturing{}

	// Enforcer must allow "weather-plugin" to use tool:get_weather.
	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("weather-plugin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  capturer,
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-1",
			Name:      "get_weather",
			Arguments: `{"city":"London"}`,
		},
	}

	sm := newMockSessionManager()
	ctx := context.Background()
	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	cfg := newTestLoopConfig(t)
	cfg.SessionManager = sm
	cfg.ProviderRouter = &mockProviderRouter{provider: toolCallProvider}
	cfg.ToolDispatcher = dispatcher
	cfg.ToolRegistry = registry
	loop, err := agent.NewLoop(cfg)
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

	// The plugin executor should have been called with "weather-plugin", not "builtin".
	capturer.mu.Lock()
	pluginName := capturer.lastPluginName
	capturer.mu.Unlock()
	assert.Equal(t, "weather-plugin", pluginName, "tool dispatcher should resolve plugin name from registry")
}

func TestToolDispatcher_FallsBackToBuiltin(t *testing.T) {
	// Registry exists but does NOT contain "get_weather".
	registry := agent.NewToolRegistry()
	registry.Register("some_other_tool", "other-plugin", provider.ToolDefinition{Name: "some_other_tool"})

	// Create a capturing plugin executor that records the plugin name.
	capturer := &mockPluginExecutorCapturing{}

	// Enforcer must allow "builtin" to use tool:get_weather.
	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("builtin", security.NewCapabilitySet("tool.*"), security.NewCapabilitySet())

	dispatcher, err := agent.NewToolDispatcher(agent.ToolDispatcherConfig{
		Enforcer:       enforcer,
		PluginManager:  capturer,
		AuditStore:     newMockAuditStore(),
		DefaultTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	toolCallProvider := &mockProviderToolCall{
		toolCall: &provider.ToolCall{
			ID:        "tc-1",
			Name:      "get_weather",
			Arguments: `{"city":"Paris"}`,
		},
	}

	sm := newMockSessionManager()
	ctx := context.Background()
	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)

	cfg := newTestLoopConfig(t)
	cfg.SessionManager = sm
	cfg.ProviderRouter = &mockProviderRouter{provider: toolCallProvider}
	cfg.ToolDispatcher = dispatcher
	cfg.ToolRegistry = registry
	loop, err := agent.NewLoop(cfg)
	require.NoError(t, err)

	out, err := loop.ProcessMessage(ctx, agent.InboundMessage{
		SessionID:       session.ID,
		WorkspaceID:     "ws-1",
		UserID:          "user-1",
		Content:         "What is the weather in Paris?",
		WorkspaceAllow:  security.NewCapabilitySet("tool.*"),
		UserPermissions: security.NewCapabilitySet("tool.*"),
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	// The plugin executor should have been called with "builtin" (fallback).
	capturer.mu.Lock()
	pluginName := capturer.lastPluginName
	capturer.mu.Unlock()
	assert.Equal(t, "builtin", pluginName, "tool dispatcher should fall back to builtin when tool not in registry")
}

// mockPluginExecutorCapturing captures the plugin name passed to ExecuteTool.
type mockPluginExecutorCapturing struct {
	mu             sync.Mutex
	lastPluginName string
}

func (m *mockPluginExecutorCapturing) ExecuteTool(_ context.Context, pluginName, _, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastPluginName = pluginName
	return "executed", nil
}

// mockPluginExecutorTracking tracks how many times ExecuteTool was called.
type mockPluginExecutorTracking struct {
	callCount atomic.Int32
	result    string
}

func (m *mockPluginExecutorTracking) ExecuteTool(ctx context.Context, _, _, _ string) (string, error) {
	m.callCount.Add(1)
	if m.result != "" {
		return m.result, nil
	}
	return "executed", nil
}

// mockPluginExecutorError always returns an error.
type mockPluginExecutorError struct {
	err error
}

func (m *mockPluginExecutorError) ExecuteTool(ctx context.Context, _, _, _ string) (string, error) {
	return "", m.err
}

// mockPluginExecutorCtxAware checks if context is cancelled before executing.
type mockPluginExecutorCtxAware struct{}

func (m *mockPluginExecutorCtxAware) ExecuteTool(ctx context.Context, _, _, _ string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		return "executed", nil
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// PluginExecutor is the interface for executing tool calls via plugins.
type PluginExecutor interface {
	ExecuteTool(ctx context.Context, pluginName, toolName, arguments string) (string, error)
}

// ToolCallRequest represents a tool invocation request.
type ToolCallRequest struct {
	ToolName    string
	Arguments   string // JSON
	SessionID   string
	WorkspaceID string
	PluginName  string
}

// ToolResult holds the output from a tool execution.
type ToolResult struct {
	Content string
	Origin  string // "tool_output" — always tagged for injection defense
}

// ToolDispatcherConfig holds dependencies for ToolDispatcher.
type ToolDispatcherConfig struct {
	Enforcer       *security.Enforcer
	PluginManager  PluginExecutor
	AuditStore     store.AuditStore
	DefaultTimeout time.Duration
}

// ToolDispatcher dispatches tool calls with security checks, timeouts, and budgets.
type ToolDispatcher struct {
	enforcer       *security.Enforcer
	pluginManager  PluginExecutor
	auditStore     store.AuditStore
	defaultTimeout time.Duration

	// turnCallCount tracks calls within a turn for budget enforcement.
	turnCallCount atomic.Int64
}

// NewToolDispatcher creates a ToolDispatcher with the given configuration.
func NewToolDispatcher(cfg ToolDispatcherConfig) *ToolDispatcher {
	return &ToolDispatcher{
		enforcer:       cfg.Enforcer,
		pluginManager:  cfg.PluginManager,
		auditStore:     cfg.AuditStore,
		defaultTimeout: cfg.DefaultTimeout,
	}
}

// ResetTurnBudget resets the per-turn call counter. Call this at the start of
// each ProcessMessage invocation.
func (d *ToolDispatcher) ResetTurnBudget() {
	d.turnCallCount.Store(0)
}

// Execute dispatches a single tool call with capability checks, timeout, and audit logging.
func (d *ToolDispatcher) Execute(ctx context.Context, req ToolCallRequest) (*ToolResult, error) {
	// Step 1: Capability check via enforcer.
	checkReq := security.CheckRequest{
		Plugin:         req.PluginName,
		Capability:     "tool:" + req.ToolName,
		WorkspaceID:    req.WorkspaceID,
		WorkspaceAllow: security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}
	if err := d.enforcer.Check(ctx, checkReq); err != nil {
		return nil, err
	}

	// Step 2: Apply timeout if configured.
	execCtx := ctx
	if d.defaultTimeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, d.defaultTimeout)
		defer cancel()
	}

	// Step 3: Execute tool via plugin.
	content, err := d.pluginManager.ExecuteTool(execCtx, req.PluginName, req.ToolName, req.Arguments)
	if err != nil {
		// Wrap context deadline exceeded as a tool timeout error.
		if execCtx.Err() == context.DeadlineExceeded {
			return nil, sigilerr.Wrap(
				err,
				sigilerr.CodeAgentToolTimeout,
				fmt.Sprintf("tool %q execution timeout", req.ToolName),
				sigilerr.FieldPlugin(req.PluginName),
				sigilerr.FieldSessionID(req.SessionID),
			)
		}
		return nil, sigilerr.Wrap(
			err,
			sigilerr.CodePluginRuntimeCallFailure,
			fmt.Sprintf("executing tool %q via plugin %q", req.ToolName, req.PluginName),
			sigilerr.FieldPlugin(req.PluginName),
			sigilerr.FieldSessionID(req.SessionID),
		)
	}

	// Step 4: Tag result with origin for injection defense.
	result := &ToolResult{
		Content: content,
		Origin:  "tool_output",
	}

	// Step 5: Audit log the execution.
	d.auditToolExecution(ctx, req, "ok")

	return result, nil
}

// ExecuteForTurn wraps Execute with per-turn budget tracking. The budget counter
// is shared across calls; call ResetTurnBudget at the start of each turn.
func (d *ToolDispatcher) ExecuteForTurn(ctx context.Context, req ToolCallRequest, maxCalls int) (*ToolResult, error) {
	count := d.turnCallCount.Add(1)
	if int(count) > maxCalls {
		return nil, sigilerr.New(
			sigilerr.CodeAgentToolBudgetExceeded,
			fmt.Sprintf("tool call budget exceeded: %d/%d calls used", count, maxCalls),
			sigilerr.FieldSessionID(req.SessionID),
			sigilerr.FieldWorkspaceID(req.WorkspaceID),
		)
	}

	return d.Execute(ctx, req)
}

func (d *ToolDispatcher) auditToolExecution(ctx context.Context, req ToolCallRequest, result string) {
	if d.auditStore == nil {
		return
	}

	entry := &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      "tool_dispatch",
		Actor:       req.PluginName,
		Plugin:      req.PluginName,
		WorkspaceID: req.WorkspaceID,
		SessionID:   req.SessionID,
		Details: map[string]any{
			"tool_name": req.ToolName,
		},
		Result: result,
	}

	// Best-effort audit; do not fail the tool execution on audit errors.
	_ = d.auditStore.Append(ctx, entry)
}

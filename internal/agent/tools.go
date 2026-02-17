// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ToolRegistry maps tool names to the plugin that provides them and stores
// tool definitions so the agent loop can send them to LLM providers.
type ToolRegistry interface {
	// LookupPlugin returns the plugin name that provides the given tool.
	// Returns ("builtin", true) for built-in tools.
	// Returns ("", false) if the tool is not registered.
	LookupPlugin(toolName string) (pluginName string, ok bool)

	// GetToolDefinitions returns all registered tool definitions for inclusion
	// in ChatRequest.Tools. The returned slice is safe for concurrent use.
	GetToolDefinitions() []provider.ToolDefinition
}

// toolEntry holds the plugin name and definition for a registered tool.
type toolEntry struct {
	pluginName string
	definition provider.ToolDefinition
}

// SimpleToolRegistry is a thread-safe in-memory implementation of ToolRegistry.
type SimpleToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]*toolEntry
}

// NewToolRegistry creates an empty SimpleToolRegistry.
func NewToolRegistry() *SimpleToolRegistry {
	return &SimpleToolRegistry{
		tools: make(map[string]*toolEntry),
	}
}

// Register maps a tool name to the plugin that provides it along with its
// definition (schema) for LLM requests.
func (r *SimpleToolRegistry) Register(toolName, pluginName string, def provider.ToolDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[toolName] = &toolEntry{
		pluginName: pluginName,
		definition: def,
	}
}

// LookupPlugin returns the plugin name for the given tool.
func (r *SimpleToolRegistry) LookupPlugin(toolName string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.tools[toolName]
	if !ok {
		return "", false
	}
	return entry.pluginName, true
}

// GetToolDefinitions returns all registered tool definitions.
func (r *SimpleToolRegistry) GetToolDefinitions() []provider.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	defs := make([]provider.ToolDefinition, 0, len(r.tools))
	for _, entry := range r.tools {
		defs = append(defs, entry.definition)
	}
	return defs
}

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
	TurnID      string // Unique identifier for budget scoping

	// WorkspaceAllow is the workspace-scoped capability allowlist.
	// The enforcer intersects plugin capabilities with this set;
	// a tool call is denied unless the workspace allows the capability.
	// A zero-value (empty) set denies all capabilities.
	WorkspaceAllow security.CapabilitySet

	// UserPermissions is the user-scoped capability set.
	// The enforcer intersects plugin capabilities with this set;
	// a tool call is denied unless the user has the required permission.
	// A zero-value (empty) set denies all capabilities.
	UserPermissions security.CapabilitySet
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

// turnBudget tracks call count for a single turn.
type turnBudget struct {
	count atomic.Int64
}

// ToolDispatcher dispatches tool calls with security checks, timeouts, and budgets.
type ToolDispatcher struct {
	enforcer       *security.Enforcer
	pluginManager  PluginExecutor
	auditStore     store.AuditStore
	defaultTimeout time.Duration

	// turnBudgets tracks per-turn call counts keyed by TurnID.
	turnBudgets sync.Map // map[string]*turnBudget

	// auditFailCount tracks consecutive audit append failures for monitoring.
	auditFailCount atomic.Int64
}

// NewToolDispatcher creates a ToolDispatcher with the given configuration.
// Returns an error if required fields are nil.
func NewToolDispatcher(cfg ToolDispatcherConfig) (*ToolDispatcher, error) {
	if cfg.Enforcer == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Enforcer is required")
	}
	if cfg.PluginManager == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "PluginManager is required")
	}

	return &ToolDispatcher{
		enforcer:       cfg.Enforcer,
		pluginManager:  cfg.PluginManager,
		auditStore:     cfg.AuditStore,
		defaultTimeout: cfg.DefaultTimeout,
	}, nil
}

// ClearTurn removes the budget entry for the given turn ID, freeing memory.
// Call this after a turn completes.
func (d *ToolDispatcher) ClearTurn(turnID string) {
	d.turnBudgets.Delete(turnID)
}

// Execute dispatches a single tool call with capability checks, timeout, and audit logging.
func (d *ToolDispatcher) Execute(ctx context.Context, req ToolCallRequest) (*ToolResult, error) {
	// Step 1: Capability check via enforcer.
	// The intersection of plugin ∩ workspace ∩ user capabilities
	// determines whether the tool call is permitted.
	checkReq := security.CheckRequest{
		Plugin:          req.PluginName,
		Capability:      "tool." + req.ToolName,
		WorkspaceID:     req.WorkspaceID,
		WorkspaceAllow:  req.WorkspaceAllow,
		UserPermissions: req.UserPermissions,
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

// ExecuteForTurn wraps Execute with per-turn budget tracking. Each unique TurnID
// gets its own independent budget counter.
func (d *ToolDispatcher) ExecuteForTurn(ctx context.Context, req ToolCallRequest, maxCalls int) (*ToolResult, error) {
	if req.TurnID == "" {
		return nil, sigilerr.New(
			sigilerr.CodeAgentLoopInvalidInput,
			"TurnID is required for budget tracking",
		)
	}

	// Load or create budget tracker for this turn. LoadOrStore guarantees the
	// value is *turnBudget because we only ever store values of that type.
	budget, _ := d.turnBudgets.LoadOrStore(req.TurnID, &turnBudget{})
	tb := budget.(*turnBudget)

	count := tb.count.Add(1)
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

	details := map[string]any{
		"tool_name": req.ToolName,
	}

	entry := &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      "tool_dispatch",
		Actor:       req.PluginName,
		Plugin:      req.PluginName,
		WorkspaceID: req.WorkspaceID,
		SessionID:   req.SessionID,
		Details:     details,
		Result:      result,
	}

	// Best-effort audit; do not fail the tool execution on audit errors.
	if err := d.auditStore.Append(ctx, entry); err != nil {
		consecutive := d.auditFailCount.Add(1)
		logLevel := slog.LevelWarn
		if consecutive >= 3 {
			logLevel = slog.LevelError
		}
		slog.Log(ctx, logLevel, "audit store append failed",
			"error", err,
			"plugin", req.PluginName,
			"tool", req.ToolName,
			"session_id", req.SessionID,
			"consecutive_failures", consecutive,
		)
	} else {
		d.auditFailCount.Store(0)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ToolRegistry maps tool names to the plugin that provides them.
// The agent loop uses this to resolve PluginName for capability enforcement.
type ToolRegistry interface {
	// LookupPlugin returns the plugin name that provides the given tool.
	// Returns ("builtin", true) for built-in tools.
	// Returns ("", false) if the tool is not registered.
	LookupPlugin(toolName string) (pluginName string, ok bool)
}

// SimpleToolRegistry is a thread-safe in-memory implementation of ToolRegistry.
type SimpleToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]string // toolName → pluginName
}

// NewToolRegistry creates an empty SimpleToolRegistry.
func NewToolRegistry() *SimpleToolRegistry {
	return &SimpleToolRegistry{
		tools: make(map[string]string),
	}
}

// Register maps a tool name to the plugin that provides it.
func (r *SimpleToolRegistry) Register(toolName, pluginName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[toolName] = pluginName
}

// LookupPlugin returns the plugin name for the given tool.
func (r *SimpleToolRegistry) LookupPlugin(toolName string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.tools[toolName]
	return name, ok
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
	Content    string
	Origin     string      // "tool_output" — always tagged for injection defense
	ScanResult *ScanResult // Optional scan metadata for suspicious content
}

// ScanResult contains injection scanning metadata for tool outputs.
type ScanResult struct {
	Suspicious bool     // True if suspicious patterns were detected
	Patterns   []string // Names of matched patterns
	Score      float64  // Confidence score (0.0-1.0, higher = more suspicious)
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
		Capability:      "tool:" + req.ToolName,
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

	// Step 5: Scan for prompt injection patterns.
	scanResult := scanToolOutput(content)
	result.ScanResult = scanResult

	if scanResult.Suspicious {
		slog.Warn("suspicious content detected in tool output",
			"plugin", req.PluginName,
			"tool", req.ToolName,
			"session_id", req.SessionID,
			"patterns", scanResult.Patterns,
			"score", scanResult.Score,
		)
	}

	// Step 6: Audit log the execution.
	auditResult := "ok"
	if scanResult.Suspicious {
		auditResult = "ok_suspicious_content"
	}
	d.auditToolExecution(ctx, req, auditResult, scanResult)

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

func (d *ToolDispatcher) auditToolExecution(ctx context.Context, req ToolCallRequest, result string, scanResult *ScanResult) {
	if d.auditStore == nil {
		return
	}

	details := map[string]any{
		"tool_name": req.ToolName,
	}

	// Include scan metadata if present.
	if scanResult != nil && scanResult.Suspicious {
		details["scan_suspicious"] = scanResult.Suspicious
		details["scan_patterns"] = scanResult.Patterns
		details["scan_score"] = scanResult.Score
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
	_ = d.auditStore.Append(ctx, entry)
}

// scanToolOutput scans tool output for prompt injection patterns.
// Returns metadata flagging suspicious content.
func scanToolOutput(output string) *ScanResult {
	if output == "" {
		return &ScanResult{
			Suspicious: false,
			Patterns:   nil,
			Score:      0.0,
		}
	}

	// Convert to lowercase for case-insensitive matching.
	lower := strings.ToLower(output)

	// Pattern definitions: each pattern has a name and detection strings.
	type pattern struct {
		name    string
		phrases []string
	}

	patterns := []pattern{
		{
			name: "system_prompt_override",
			phrases: []string{
				"ignore previous instructions",
				"ignore all previous instructions",
				"disregard previous instructions",
				"forget previous instructions",
				"you are now",
				"system:",
				"system prompt",
				"new instructions",
				"override instructions",
			},
		},
		{
			name: "role_confusion",
			phrases: []string{
				"### human:",
				"### assistant:",
				"user:",
				"assistant:",
				"<|im_start|>",
				"<|im_end|>",
				"[system]",
				"[user]",
				"[assistant]",
			},
		},
		{
			name: "instruction_injection",
			phrases: []string{
				"do not follow",
				"disregard",
				"override",
				"ignore the",
				"forget the",
				"don't follow",
				"you must",
				"you should now",
				"instead, you will",
			},
		},
	}

	var matchedPatterns []string
	matchCount := 0

	for _, p := range patterns {
		for _, phrase := range p.phrases {
			if strings.Contains(lower, phrase) {
				matchedPatterns = append(matchedPatterns, p.name)
				matchCount++
				break // Only count each pattern once per tool output.
			}
		}
	}

	suspicious := len(matchedPatterns) > 0

	// Calculate score based on number of distinct patterns matched.
	// Score = (patterns matched / total patterns) capped at 1.0.
	var score float64
	if suspicious {
		score = float64(len(matchedPatterns)) / float64(len(patterns))
		if score > 1.0 {
			score = 1.0
		}
	}

	return &ScanResult{
		Suspicious: suspicious,
		Patterns:   matchedPatterns,
		Score:      score,
	}
}

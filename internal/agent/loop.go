// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ScannerModes holds the per-stage detection modes.
type ScannerModes struct {
	Input  scanner.Mode
	Tool   scanner.Mode
	Output scanner.Mode
}

// Validate checks that all scanner mode fields are non-empty and valid.
func (m ScannerModes) Validate() error {
	for _, pair := range []struct {
		name string
		mode scanner.Mode
	}{
		{"Input", m.Input},
		{"Tool", m.Tool},
		{"Output", m.Output},
	} {
		if pair.mode == "" {
			return sigilerr.Errorf(sigilerr.CodeAgentLoopInvalidInput,
				"ScannerModes.%s is required", pair.name)
		}
		if !pair.mode.Valid() {
			return sigilerr.Errorf(sigilerr.CodeAgentLoopInvalidInput,
				"invalid ScannerModes.%s: %q", pair.name, pair.mode)
		}
	}
	return nil
}

// defaultMaxToolCallsPerTurn is the default maximum number of tool calls
// allowed in a single turn when MaxToolCallsPerTurn is not configured.
const defaultMaxToolCallsPerTurn = 10

// maxToolLoopIterations is the maximum number of tool-loop iterations
// (LLM call → tool dispatch → re-call) before the loop is terminated.
const maxToolLoopIterations = 5

// builtinPluginName is the default plugin name used for tools that are
// not registered in a ToolRegistry. When a ToolRegistry is configured,
// runToolLoop resolves the plugin name from the registry; tools not
// found in the registry fall back to this value.
const builtinPluginName = "builtin"

// defaultSystemPrompt is the baseline system instruction sent to the LLM via
// ChatRequest.SystemPrompt. Providers use their native mechanism to inject it
// (e.g. Anthropic's system param, Google's SystemInstruction, OpenAI's system role).
const defaultSystemPrompt = "You are a helpful assistant."

// InboundMessage is the input to the agent loop.
type InboundMessage struct {
	SessionID   string
	WorkspaceID string
	UserID      string
	Content     string

	// WorkspaceAllow is the set of capabilities granted to the workspace.
	// Used by the tool loop to enforce workspace-level capability policy.
	// A zero-value (empty) set causes the enforcer to deny all tool calls (fail-closed).
	WorkspaceAllow security.CapabilitySet

	// UserPermissions is the set of capabilities granted to the user.
	// Used by the tool loop to enforce user-level capability policy.
	// A zero-value (empty) set causes the enforcer to deny all tool calls (fail-closed).
	UserPermissions security.CapabilitySet
}

// OutboundMessage is the output from the agent loop.
type OutboundMessage struct {
	SessionID string
	Content   string
	Usage     *provider.Usage
}

// LoopHooks provides optional test hooks for each pipeline stage.
type LoopHooks struct {
	OnReceive func()
	OnPrepare func()
	OnCallLLM func()
	OnProcess func()
	OnRespond func()
	OnAudit   func()
}

// LoopConfig holds dependencies for the Loop.
type LoopConfig struct {
	SessionManager      *SessionManager
	Enforcer            *security.Enforcer
	ProviderRouter      provider.Router
	AuditStore          store.AuditStore
	ToolDispatcher      *ToolDispatcher
	ToolRegistry        ToolRegistry
	MaxToolCallsPerTurn int
	Hooks               *LoopHooks
	Scanner             scanner.Scanner
	ScannerModes        ScannerModes
}

// Loop is the agent's core processing pipeline.
type Loop struct {
	sessions            *SessionManager
	enforcer            *security.Enforcer
	providerRouter      provider.Router
	auditStore          store.AuditStore
	toolDispatcher      *ToolDispatcher
	toolRegistry        ToolRegistry
	maxToolCallsPerTurn int
	hooks               *LoopHooks
	scanner             scanner.Scanner
	scannerModes        ScannerModes
	auditFailCount      atomic.Int64
	scannerFailCount    atomic.Int64
}

// NewLoop creates a Loop with the given dependencies.
// Required: SessionManager, Enforcer, ProviderRouter, Scanner, and ScannerModes
// (all three stage modes must be valid). Returns an error if any required
// dependency is nil or invalid.
func NewLoop(cfg LoopConfig) (*Loop, error) {
	if cfg.SessionManager == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "SessionManager is required")
	}
	if cfg.Enforcer == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Enforcer is required")
	}
	if cfg.ProviderRouter == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "ProviderRouter is required")
	}
	if cfg.Scanner == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Scanner is required")
	}
	if err := cfg.ScannerModes.Validate(); err != nil {
		return nil, err
	}

	maxCalls := cfg.MaxToolCallsPerTurn
	if maxCalls <= 0 {
		maxCalls = defaultMaxToolCallsPerTurn
	}

	return &Loop{
		sessions:            cfg.SessionManager,
		enforcer:            cfg.Enforcer,
		providerRouter:      cfg.ProviderRouter,
		auditStore:          cfg.AuditStore,
		toolDispatcher:      cfg.ToolDispatcher,
		toolRegistry:        cfg.ToolRegistry,
		maxToolCallsPerTurn: maxCalls,
		hooks:               cfg.Hooks,
		scanner:             cfg.Scanner,
		scannerModes:        cfg.ScannerModes,
	}, nil
}

// ProcessMessage executes the 7-step agent pipeline:
// RECEIVE → PREPARE → CALL_LLM → PROCESS → TOOL_LOOP → RESPOND → AUDIT.
func (l *Loop) ProcessMessage(ctx context.Context, msg InboundMessage) (*OutboundMessage, error) {
	// Step 1: RECEIVE — validate input.
	if err := l.validateInput(msg); err != nil {
		return nil, err
	}
	l.fireHook(l.hooks, hookReceive)

	// Step 2: PREPARE — load session, build message array.
	session, messages, err := l.prepare(ctx, msg)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "prepare: session %s", msg.SessionID)
	}
	l.fireHook(l.hooks, hookPrepare)

	// Step 3: CALL_LLM — route to provider and call Chat.
	eventCh, selectedProvider, err := l.callLLM(ctx, msg.WorkspaceID, session, messages)
	if err != nil {
		return nil, err
	}
	l.fireHook(l.hooks, hookCallLLM)

	// Step 4: PROCESS — buffer text deltas and collect tool calls.
	text, toolCalls, usage, streamErr := l.processEvents(eventCh)
	l.fireHook(l.hooks, hookProcess)

	// Account token usage even if the stream errored — the provider may have
	// emitted usage before the failure and those tokens were real consumption.
	if err := l.accountUsage(ctx, session, usage); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeStoreDatabaseFailure, "budget accounting: session %s", msg.SessionID)
	}

	// If the stream emitted a fatal error, discard partial output and fail the turn.
	// Record the failure for health tracking so the circuit breaker can respond to
	// persistent mid-stream failures (e.g., connection drops, malformed responses).
	if streamErr != nil {
		l.recordProviderFailure(selectedProvider)
		return nil, sigilerr.Wrapf(streamErr, sigilerr.CodeProviderUpstreamFailure, "stream error: session %s", msg.SessionID)
	}

	// Step 5: TOOL_LOOP — dispatch tool calls and re-call the LLM.
	if l.toolDispatcher != nil && len(toolCalls) > 0 {
		var loopText string
		var loopUsage *provider.Usage
		loopText, loopUsage, err = l.runToolLoop(ctx, msg, session, messages, text, toolCalls, usage)
		if err != nil {
			return nil, err
		}
		text = loopText
		usage = loopUsage
	}

	// Step 6: RESPOND — build outbound message, persist assistant message.
	out, outputThreat, err := l.respond(ctx, msg.SessionID, text, usage)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "respond: session %s", msg.SessionID)
	}
	l.fireHook(l.hooks, hookRespond)

	// Step 7: AUDIT — log the interaction, including threat metadata if detected.
	l.audit(ctx, msg, out, outputThreat)
	l.fireHook(l.hooks, hookAudit)

	return out, nil
}

// hookKind identifies which hook to fire.
type hookKind int

const (
	hookReceive hookKind = iota
	hookPrepare
	hookCallLLM
	hookProcess
	hookRespond
	hookAudit
)

func (l *Loop) fireHook(hooks *LoopHooks, kind hookKind) {
	if hooks == nil {
		return
	}

	var fn func()
	switch kind {
	case hookReceive:
		fn = hooks.OnReceive
	case hookPrepare:
		fn = hooks.OnPrepare
	case hookCallLLM:
		fn = hooks.OnCallLLM
	case hookProcess:
		fn = hooks.OnProcess
	case hookRespond:
		fn = hooks.OnRespond
	case hookAudit:
		fn = hooks.OnAudit
	}

	if fn != nil {
		fn()
	}
}

func (l *Loop) validateInput(msg InboundMessage) error {
	var missing []string
	if msg.SessionID == "" {
		missing = append(missing, "SessionID")
	}
	if msg.WorkspaceID == "" {
		missing = append(missing, "WorkspaceID")
	}
	if msg.UserID == "" {
		missing = append(missing, "UserID")
	}
	if msg.Content == "" {
		missing = append(missing, "Content")
	}

	if len(missing) > 0 {
		return sigilerr.New(
			sigilerr.CodeAgentLoopInvalidInput,
			"missing required fields: "+strings.Join(missing, ", "),
			sigilerr.FieldSessionID(msg.SessionID),
			sigilerr.FieldWorkspaceID(msg.WorkspaceID),
		)
	}
	return nil
}

// validateSessionBoundary ensures the loaded session belongs to the workspace
// and user specified in the inbound message. This MUST be called before any
// store writes to enforce session isolation.
func (l *Loop) validateSessionBoundary(session *store.Session, msg InboundMessage) error {
	if session.WorkspaceID != msg.WorkspaceID {
		return sigilerr.New(
			sigilerr.CodeAgentSessionBoundaryMismatch,
			"session workspace mismatch: session belongs to workspace "+session.WorkspaceID+", got "+msg.WorkspaceID,
			sigilerr.FieldSessionID(session.ID),
			sigilerr.FieldWorkspaceID(msg.WorkspaceID),
		)
	}
	if session.UserID != msg.UserID {
		return sigilerr.New(
			sigilerr.CodeAgentSessionBoundaryMismatch,
			"session user mismatch: session belongs to user "+session.UserID+", got "+msg.UserID,
			sigilerr.FieldSessionID(session.ID),
			sigilerr.FieldUserID(msg.UserID),
		)
	}
	return nil
}

// validateSessionStatus rejects sessions that are not in the active state.
// Paused and archived sessions cannot accept new messages.
func (l *Loop) validateSessionStatus(session *store.Session) error {
	if session.Status != store.SessionStatusActive {
		return sigilerr.New(
			sigilerr.CodeAgentSessionInactive,
			"session is "+string(session.Status)+", only active sessions accept messages",
			sigilerr.FieldSessionID(session.ID),
		)
	}
	return nil
}

func (l *Loop) prepare(ctx context.Context, msg InboundMessage) (*store.Session, []provider.Message, error) {
	// Input scanning — reject prompt injection before loading session state.
	// Scanning first avoids spending resources on session load, boundary
	// validation, and status checks for messages that will be rejected.
	scanned, inputThreat, scanErr := l.scanContent(ctx, msg.Content,
		scanner.StageInput, scanner.OriginUser, l.scannerModes.Input,
		"session_id", msg.SessionID, "workspace_id", msg.WorkspaceID,
	)
	if scanErr != nil {
		return nil, nil, scanErr
	}
	// Note: msg.Content is replaced with the scanner-normalized form
	// (NFKC + zero-width stripped). The normalized content is persisted,
	// not the original user input.
	msg.Content = scanned

	session, err := l.sessions.Get(ctx, msg.SessionID)
	if err != nil {
		return nil, nil, err
	}

	// Validate session boundary: workspace and user must match the inbound message.
	if err := l.validateSessionBoundary(session, msg); err != nil {
		return nil, nil, err
	}

	// Reject non-active sessions (archived, paused, etc.).
	if err := l.validateSessionStatus(session); err != nil {
		return nil, nil, err
	}

	// Append the incoming user message to the session store.
	userMsg := &store.Message{
		ID:        uuid.New().String(),
		SessionID: msg.SessionID,
		Role:      store.MessageRoleUser,
		Content:   msg.Content,
		Threat:    inputThreat,
		CreatedAt: time.Now(),
	}
	if err := l.sessions.AppendMessage(ctx, msg.SessionID, userMsg); err != nil {
		return nil, nil, err
	}

	// Load conversation history from the active window.
	history, err := l.sessions.GetActiveWindow(ctx, msg.SessionID, 50)
	if err != nil {
		return nil, nil, err
	}

	// Build the message array for the LLM:
	// active window history (which already includes the user message we just appended).
	// The system prompt is set separately via ChatRequest.SystemPrompt so that all
	// providers (Anthropic, Google, OpenAI) handle it through their native mechanism.
	var messages []provider.Message
	for _, m := range history {
		messages = append(messages, provider.Message{
			Role:       m.Role,
			Content:    m.Content,
			ToolCallID: m.ToolCallID,
			ToolName:   m.ToolName,
			Origin:     originFromRole(m.Role),
		})
	}

	return session, messages, nil
}

// callLLM calls the provider route with failover support. Failover only covers
// first-event failures (auth errors, rate limits, provider down). Mid-stream
// failures are not retried because replaying the full conversation to a fallback
// provider requires buffering all events and resending all messages — significant
// complexity with partial-output ambiguity. Mid-stream errors surface to the caller
// via processEvents. See D036 in docs/decisions/decision-log.md for design rationale.
// Returns the event channel and the provider that was successfully selected (for health tracking).
func (l *Loop) callLLM(ctx context.Context, workspaceID string, session *store.Session, messages []provider.Message) (<-chan provider.ChatEvent, provider.Provider, error) {
	modelName := session.ModelOverride
	if modelName == "" {
		modelName = "default"
	}

	// Build budget from session token limits so the router can enforce them.
	budget, err := provider.NewBudget(
		session.TokenBudget.MaxPerSession,
		session.TokenBudget.UsedSession,
		0, 0, 0, 0, // cents budgets not yet tracked
	)
	if err != nil {
		return nil, nil, sigilerr.Wrap(err, sigilerr.CodeAgentLoopInvalidInput, "invalid budget")
	}

	maxAttempts := l.providerRouter.MaxAttempts()
	var lastErr error
	var triedProviders []string
	// Accumulate provider failures for comprehensive error reporting.
	// Each element is "providerName: error message".
	var providerFailures []string
	for attempt := 0; attempt < maxAttempts; attempt++ {
		prov, resolvedModel, err := l.providerRouter.RouteWithBudget(ctx, workspaceID, modelName, budget, triedProviders)
		if err != nil {
			// Propagate specific routing errors directly instead of masking
			// them as "all providers unavailable".
			if sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded) ||
				sigilerr.HasCode(err, sigilerr.CodeProviderInvalidModelRef) ||
				sigilerr.HasCode(err, sigilerr.CodeProviderNoDefault) {
				return nil, nil, err
			}
			lastErr = err
			// Record routing failures so users can see which providers were skipped.
			providerFailures = append(providerFailures, fmt.Sprintf("route attempt %d: %s", attempt+1, err.Error()))
			continue
		}

		triedProviders = append(triedProviders, prov.Name())

		req := provider.ChatRequest{
			Model:        resolvedModel,
			Messages:     messages,
			SystemPrompt: defaultSystemPrompt,
			Options:      provider.ChatOptions{Stream: true},
		}
		if l.toolRegistry != nil {
			req.Tools = l.toolRegistry.GetToolDefinitions()
		}

		eventCh, err := prov.Chat(ctx, req)
		if err != nil {
			// Mark provider unhealthy so the next Route call skips it
			// via the failover chain. The HealthTracker's cooldown acts
			// as a circuit breaker, re-enabling the provider after the
			// cooldown period for recovery.
			l.recordProviderFailure(prov)
			lastErr = sigilerr.Wrap(err, sigilerr.CodeProviderUpstreamFailure, fmt.Sprintf("chat call to %s", prov.Name()), sigilerr.FieldProvider(prov.Name()))
			providerFailures = append(providerFailures, fmt.Sprintf("%s: %s", prov.Name(), err.Error()))
			continue
		}

		// Peek at the first event to detect immediate upstream failures
		// (auth errors, rate limits, provider down). Pre-stream failures are
		// recorded by this caller; providers record success only on stream
		// completion via RecordSuccess(), so the next Route call will skip
		// this provider via the failover chain if needed.
		firstEvent, ok := <-eventCh
		if !ok {
			l.recordProviderFailure(prov)
			lastErr = sigilerr.New(sigilerr.CodeProviderUpstreamFailure, fmt.Sprintf("provider %s: stream closed without events", prov.Name()), sigilerr.FieldProvider(prov.Name()))
			providerFailures = append(providerFailures, fmt.Sprintf("%s: stream closed without events", prov.Name()))
			continue
		}

		if firstEvent.Type == provider.EventTypeError {
			l.recordProviderFailure(prov)
			lastErr = sigilerr.New(sigilerr.CodeProviderUpstreamFailure, fmt.Sprintf("provider %s: %s", prov.Name(), firstEvent.Error), sigilerr.FieldProvider(prov.Name()))
			providerFailures = append(providerFailures, fmt.Sprintf("%s: %s", prov.Name(), firstEvent.Error))
			l.drainEventChannel(eventCh)
			continue
		}

		// First event is valid — wrap it back with the rest of the stream.
		// fallback provider requires buffering all events and resending messages.
		// Mid-stream errors surface to the caller via processEvents.
		wrappedCh := make(chan provider.ChatEvent, cap(eventCh)+1)
		wrappedCh <- firstEvent
		go func() {
			defer close(wrappedCh)
			for ev := range eventCh {
				wrappedCh <- ev
			}
		}()
		return wrappedCh, prov, nil
	}

	// All providers failed. Build comprehensive error message showing all failures.
	if len(providerFailures) > 0 {
		combinedMsg := fmt.Sprintf("all providers failed for workspace %s: %s", workspaceID, strings.Join(providerFailures, "; "))
		if lastErr != nil {
			// For single provider failure, preserve the original error code if available.
			// For multiple failures or routing errors, use CodeProviderAllUnavailable.
			code := sigilerr.CodeOf(lastErr)
			if len(providerFailures) == 1 && code != "" {
				// Single failure with a specific error code: preserve it.
				return nil, nil, sigilerr.Errorf(code, "%s", combinedMsg)
			}
			// Multiple failures or non-sigilerr error: all providers unavailable.
			// Create new error instead of wrapping to ensure correct code.
			return nil, nil, sigilerr.New(sigilerr.CodeProviderAllUnavailable, combinedMsg)
		}
		return nil, nil, sigilerr.New(sigilerr.CodeProviderAllUnavailable, combinedMsg)
	}
	return nil, nil, sigilerr.New(sigilerr.CodeProviderAllUnavailable, "no providers available for workspace "+workspaceID)
}

func (l *Loop) processEvents(eventCh <-chan provider.ChatEvent) (string, []*provider.ToolCall, *provider.Usage, error) {
	var buf strings.Builder
	var toolCalls []*provider.ToolCall
	var usage *provider.Usage
	var streamErr error

	for ev := range eventCh {
		// Validate event Type/payload consistency at the consumption boundary.
		if err := ev.Validate(); err != nil {
			return "", nil, nil, sigilerr.Wrap(err, sigilerr.CodeProviderResponseInvalid, "invalid event from provider")
		}

		switch ev.Type {
		case provider.EventTypeTextDelta:
			buf.WriteString(ev.Text)
		case provider.EventTypeUsage:
			usage = ev.Usage
		case provider.EventTypeDone:
			if ev.Usage != nil {
				usage = ev.Usage
			}
		case provider.EventTypeToolCall:
			if ev.ToolCall != nil {
				toolCalls = append(toolCalls, ev.ToolCall)
			}
		case provider.EventTypeError:
			// Capture fatal stream errors. Partial text is discarded when error occurs.
			streamErr = sigilerr.New(sigilerr.CodeProviderUpstreamFailure, ev.Error)
		}
	}

	return buf.String(), toolCalls, usage, streamErr
}

// recordProviderFailure marks a provider as unhealthy if it implements HealthReporter.
// Used to trigger failover to the next provider in the chain via the HealthTracker's
// cooldown-based circuit breaker.
func (l *Loop) recordProviderFailure(prov provider.Provider) {
	if hr, ok := prov.(provider.HealthReporter); ok {
		hr.RecordFailure()
	}
}

// drainEventChannel consumes all remaining events from ch to prevent the
// goroutine writing to ch from blocking on a full buffer. Blocks until ch is closed.
func (l *Loop) drainEventChannel(ch <-chan provider.ChatEvent) {
	for range ch {
	}
}

// accountUsage increments the session's token budget counters with the
// tokens consumed by an LLM call and persists the update. Returns an error
// if persistence fails (fail-closed: budget counters must be durable to
// prevent over-budget sessions after restart).
func (l *Loop) accountUsage(ctx context.Context, session *store.Session, usage *provider.Usage) error {
	if usage == nil {
		return nil
	}
	total := usage.InputTokens + usage.OutputTokens
	session.TokenBudget.UsedSession += total
	session.TokenBudget.UsedHour += total
	session.TokenBudget.UsedDay += total

	if err := l.sessions.Update(ctx, session); err != nil {
		return sigilerr.Errorf(sigilerr.CodeAgentLoopFailure, "persisting token budget counters: %w", err)
	}
	return nil
}

// runToolLoop executes the bounded inner tool loop: dispatch tool calls,
// append results to message history, re-call the LLM, and repeat if
// more tool calls are emitted. Bounded by maxToolLoopIterations.
func (l *Loop) runToolLoop(
	ctx context.Context,
	msg InboundMessage,
	session *store.Session,
	messages []provider.Message,
	initialText string,
	toolCalls []*provider.ToolCall,
	initialUsage *provider.Usage,
) (string, *provider.Usage, error) {
	turnID := uuid.New().String()
	defer l.toolDispatcher.ClearTurn(turnID)

	currentMessages := make([]provider.Message, len(messages))
	copy(currentMessages, messages)
	currentToolCalls := toolCalls
	text := initialText
	var usage *provider.Usage

	for range maxToolLoopIterations {
		// If the LLM emitted text alongside tool calls, persist it as an
		// assistant message so the conversation history stays coherent.
		if text != "" {
			// Output scanning — filter secrets from intermediate assistant text
			// before persisting to session history.
			scannedText, intermediateThreat, scanErr := l.scanContent(ctx, text,
				scanner.StageOutput, scanner.OriginSystem, l.scannerModes.Output,
				"session_id", msg.SessionID, "workspace_id", msg.WorkspaceID,
			)
			if scanErr != nil {
				return "", nil, scanErr
			}
			text = scannedText

			assistantMsg := &store.Message{
				ID:        uuid.New().String(),
				SessionID: msg.SessionID,
				Role:      store.MessageRoleAssistant,
				Content:   text,
				Threat:    intermediateThreat,
				CreatedAt: time.Now(),
			}
			if err := l.sessions.AppendMessage(ctx, msg.SessionID, assistantMsg); err != nil {
				return "", nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "persisting assistant message: session %s", msg.SessionID)
			}
			currentMessages = append(currentMessages, provider.Message{
				Role:    store.MessageRoleAssistant,
				Content: text,
				Origin:  provider.OriginSystem,
			})
		}

		// Dispatch each tool call and collect results.
		for _, tc := range currentToolCalls {
			pluginName := builtinPluginName
			if l.toolRegistry != nil {
				if name, ok := l.toolRegistry.LookupPlugin(tc.Name); ok {
					pluginName = name
				}
			}

			req := ToolCallRequest{
				ToolName:        tc.Name,
				Arguments:       tc.Arguments,
				SessionID:       msg.SessionID,
				WorkspaceID:     msg.WorkspaceID,
				PluginName:      pluginName,
				TurnID:          turnID,
				WorkspaceAllow:  msg.WorkspaceAllow,
				UserPermissions: msg.UserPermissions,
			}

			result, err := l.toolDispatcher.ExecuteForTurn(ctx, req, l.maxToolCallsPerTurn)

			var resultContent string
			if err != nil {
				// On dispatch failure, send a sanitized error message as the tool
				// result so the LLM can see it without leaking internal state.
				resultContent = sanitizeToolError(err)
			} else {
				resultContent = result.Content
			}

			// Tool result scanning — check for instruction injection before persisting.
			scannedResult, toolThreat, scanErr := l.scanContent(ctx, resultContent,
				scanner.StageTool, scanner.OriginTool, l.scannerModes.Tool,
				"tool", tc.Name, "session_id", msg.SessionID, "workspace_id", msg.WorkspaceID,
			)
			if scanErr != nil {
				return "", nil, scanErr
			}
			resultContent = scannedResult

			// Persist tool result message (using scanned content).
			toolMsg := &store.Message{
				ID:         uuid.New().String(),
				SessionID:  msg.SessionID,
				Role:       store.MessageRoleTool,
				Content:    resultContent,
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
				Threat:     toolThreat,
				CreatedAt:  time.Now(),
			}
			if appendErr := l.sessions.AppendMessage(ctx, msg.SessionID, toolMsg); appendErr != nil {
				return "", nil, sigilerr.Wrapf(appendErr, sigilerr.CodeAgentLoopFailure, "persisting tool result: session %s", msg.SessionID)
			}

			currentMessages = append(currentMessages, provider.Message{
				Role:       store.MessageRoleTool,
				Content:    resultContent,
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
				Origin:     provider.OriginTool,
			})
		}

		// Re-call the LLM with updated message history.
		eventCh, toolLoopProvider, err := l.callLLM(ctx, msg.WorkspaceID, session, currentMessages)
		if err != nil {
			return "", nil, err
		}

		var streamErr error
		text, currentToolCalls, usage, streamErr = l.processEvents(eventCh)

		// Account usage even on stream errors — tokens were consumed at the provider.
		if err := l.accountUsage(ctx, session, usage); err != nil {
			return "", nil, sigilerr.Wrapf(err, sigilerr.CodeStoreDatabaseFailure, "budget accounting in tool loop: session %s", msg.SessionID)
		}
		if streamErr != nil {
			l.recordProviderFailure(toolLoopProvider)
			return "", nil, sigilerr.Wrapf(streamErr, sigilerr.CodeProviderUpstreamFailure, "stream error in tool loop: session %s", msg.SessionID)
		}

		// If no more tool calls, the loop is done.
		if len(currentToolCalls) == 0 {
			return text, usage, nil
		}
	}

	// Loop exhausted iterations with tool calls still pending.
	return "", nil, sigilerr.New(sigilerr.CodeAgentLoopFailure,
		"tool loop exceeded maximum iterations with unresolved tool calls",
		sigilerr.Field("max_iterations", maxToolLoopIterations),
		sigilerr.Field("pending_tool_calls", len(currentToolCalls)),
	)
}

func (l *Loop) respond(ctx context.Context, sessionID, text string, usage *provider.Usage) (*OutboundMessage, *store.ThreatInfo, error) {
	// Output scanning — filter secrets before persisting/returning.
	scanned, outputThreat, scanErr := l.scanContent(ctx, text,
		scanner.StageOutput, scanner.OriginSystem, l.scannerModes.Output,
		"session_id", sessionID,
	)
	if scanErr != nil {
		return nil, nil, scanErr
	}
	text = scanned

	// Persist the assistant response.
	assistantMsg := &store.Message{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		Role:      store.MessageRoleAssistant,
		Content:   text,
		Threat:    outputThreat,
		CreatedAt: time.Now(),
	}
	if err := l.sessions.AppendMessage(ctx, sessionID, assistantMsg); err != nil {
		return nil, nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "persisting assistant response: session %s", sessionID)
	}

	return &OutboundMessage{
		SessionID: sessionID,
		Content:   text,
		Usage:     usage,
	}, outputThreat, nil
}

func originFromRole(role store.MessageRole) provider.Origin {
	switch role {
	case store.MessageRoleUser:
		return provider.OriginUser
	case store.MessageRoleTool:
		return provider.OriginTool
	default:
		return provider.OriginSystem
	}
}

func (l *Loop) audit(ctx context.Context, msg InboundMessage, out *OutboundMessage, threatInfo *store.ThreatInfo) {
	if l.auditStore == nil {
		return
	}

	details := map[string]any{"content_length": len(out.Content)}

	// Finding 3: include threat metadata in audit details when threats were detected.
	if threatInfo != nil && threatInfo.Detected {
		details["threat_detected"] = true
		details["threat_rules"] = threatInfo.Rules
		details["threat_stage"] = string(threatInfo.Stage)
	}

	entry := &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      "agent_loop.message",
		Actor:       msg.UserID,
		WorkspaceID: msg.WorkspaceID,
		SessionID:   msg.SessionID,
		Details:     details,
		Result:      "ok",
	}

	// Best-effort audit; do not fail the response on audit errors.
	if err := l.auditStore.Append(ctx, entry); err != nil {
		l.auditFailCount.Add(1)
		slog.Warn("audit store append failed",
			"error", err,
			"workspace_id", msg.WorkspaceID,
			"session_id", msg.SessionID,
			"consecutive_failures", l.auditFailCount.Load(),
		)
	} else {
		l.auditFailCount.Store(0)
	}
}

// maxToolContentScanSize is the truncation limit applied to oversized tool results
// before re-scanning. A malicious tool could return content larger than the scanner's
// maximum (1MB) to trigger a content_too_large error and bypass scanning. Truncating
// to 512KB and re-scanning closes that bypass while still scanning the leading content
// where prompt-injection payloads are most likely to appear.
const maxToolContentScanSize = 512 * 1024 // 512KB

// scanContent scans content at the given stage and applies the configured mode.
// Returns the (possibly redacted) content, threat info (if a threat was detected), or an error
// if scanning fails or the mode blocks. Scanner is guaranteed non-nil by NewLoop validation.
func (l *Loop) scanContent(ctx context.Context, content string, stage scanner.Stage, origin scanner.Origin, mode scanner.Mode, logAttrs ...any) (string, *store.ThreatInfo, error) {
	scanResult, scanErr := l.scanner.Scan(ctx, content, scanner.ScanContext{
		Stage:  stage,
		Origin: origin,
	})
	if scanErr != nil {
		// For tool stage: scanner internal errors (not threat detections) are
		// best-effort — log and continue with unscanned content to preserve
		// availability. Threat detections are handled below via ApplyMode.
		// See D062 decision record for rationale.
		//
		// Exception: content_too_large errors on the tool stage are a security
		// concern (sigil-7g5.184) — a malicious plugin could deliberately return
		// >1MB content to trigger this path and bypass scanning. Instead of
		// passing unscanned content through, truncate to maxToolContentScanSize
		// and re-scan the truncated content.
		if stage == scanner.StageTool {
			if sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerContentTooLarge) {
				truncated := content[:min(len(content), maxToolContentScanSize)]
				slog.Warn("tool result exceeds scanner limit, truncating and re-scanning",
					append([]any{
						"original_size", len(content),
						"truncated_size", len(truncated),
						"stage", stage,
					}, logAttrs...)...,
				)
				reScanResult, reScanErr := l.scanner.Scan(ctx, truncated, scanner.ScanContext{
					Stage:  stage,
					Origin: origin,
				})
				if reScanErr == nil {
					// Re-scan succeeded: apply mode against the truncated+scanned result.
					return l.applyScannedResult(stage, mode, reScanResult)
				}
				// Re-scan also failed: fall through to the generic best-effort path.
				scanErr = reScanErr
			}
			consecutive := l.scannerFailCount.Add(1)
			logLevel := slog.LevelWarn
			if consecutive >= 3 {
				logLevel = slog.LevelError
			}
			slog.Log(ctx, logLevel, "scanner internal error on tool result, continuing with unscanned content",
				append([]any{
					"error", scanErr,
					"stage", stage,
					"error_code", sigilerr.CodeSecurityScannerFailure,
					"consecutive_failures", consecutive,
				}, logAttrs...)...,
			)
			return content, nil, nil
		}
		return "", nil, sigilerr.Wrapf(scanErr, sigilerr.CodeSecurityScannerFailure,
			"scanning %s content", stage,
		)
	}

	return l.applyScannedResult(stage, mode, scanResult, logAttrs...)
}

// applyScannedResult processes a successful ScanResult: resets failure counters, builds
// threat info, applies the configured mode, and returns the (possibly redacted) content.
func (l *Loop) applyScannedResult(stage scanner.Stage, mode scanner.Mode, scanResult scanner.ScanResult, logAttrs ...any) (string, *store.ThreatInfo, error) {
	// Reset the scanner fail counter on success for the tool stage.
	if stage == scanner.StageTool {
		l.scannerFailCount.Store(0)
	}

	var threat *store.ThreatInfo
	if scanResult.Threat {
		rules := make([]string, 0, len(scanResult.Matches))
		highestSeverity := scanner.Severity("")
		for _, m := range scanResult.Matches {
			rules = append(rules, m.Rule)
			attrs := append([]any{"rule", m.Rule, "severity", m.Severity, "stage", stage}, logAttrs...)
			slog.Warn("security scan threat detected", attrs...)
			if highestSeverity == "" || severityRank(m.Severity) > severityRank(highestSeverity) {
				highestSeverity = m.Severity
			}
		}
		threat = &store.ThreatInfo{
			Detected: true,
			Rules:    rules,
			Stage:    store.ScanStage(stage),
		}

		// Finding 2: enhanced flag-mode logging with match count, highest severity, and scanner mode.
		if mode == scanner.ModeFlag {
			slog.Warn("scanner flag mode: threats detected in content",
				append([]any{
					"match_count", len(scanResult.Matches),
					"highest_severity", string(highestSeverity),
					"scanner_mode", string(mode),
					"stage", stage,
				}, logAttrs...)...,
			)
		}
	}

	scanned, modeErr := scanner.ApplyMode(mode, stage, scanResult)
	if modeErr != nil {
		return "", nil, modeErr
	}

	return scanned, threat, nil
}

// severityRank returns a numeric rank for a scanner.Severity so that
// the highest severity can be determined across multiple matches.
func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityHigh:
		return 3
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 1
	default:
		return 0
	}
}

// AuditFailCount returns the current consecutive audit failure count.
// Exposed for testing to verify best-effort audit semantics.
func (l *Loop) AuditFailCount() int64 {
	return l.auditFailCount.Load()
}

// ScannerFailCount returns the current consecutive tool-stage scanner failure count.
// Exposed for testing to verify circuit breaker semantics (D062).
func (l *Loop) ScannerFailCount() int64 {
	return l.scannerFailCount.Load()
}

// sanitizeToolError returns a user-friendly error message for tool dispatch failures,
// avoiding leakage of internal paths, stack traces, or DB details to the LLM.
// The full error is logged at Warn level for debugging.
func sanitizeToolError(err error) string {
	slog.Warn("tool dispatch error", "error", err)

	code := sigilerr.CodeOf(err)
	switch {
	case code == sigilerr.CodePluginNotFound,
		code == sigilerr.CodeAgentToolBudgetExceeded,
		code == sigilerr.CodeAgentToolTimeout:
		return "tool not found"
	case code == sigilerr.CodePluginCapabilityDenied,
		code == sigilerr.CodeWorkspaceMembershipDenied:
		return "capability denied"
	case code != "":
		return "tool execution failed"
	default:
		return "tool execution failed"
	}
}

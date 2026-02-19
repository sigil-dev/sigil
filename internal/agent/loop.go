// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
)

// ScannerModes holds the per-stage detection modes.
// The zero value is intentionally invalid (all mode fields are empty strings).
// Obtain a valid value via DefaultScannerModes (exported package-level var) or
// NewScannerModesFromConfig() (public). Direct construction (ScannerModes{}) bypasses
// validation and will be rejected by LoopConfig.Validate.
type ScannerModes struct {
	Input  types.ScannerMode
	Tool   types.ScannerMode
	Output types.ScannerMode
	// DisableOriginTagging controls whether origin tags ([user_input], [tool_output])
	// are prepended to user and tool messages before sending to LLM providers.
	// The zero value (false) means tagging is enabled, which is the safe default.
	// Set to true only to explicitly disable tagging (e.g., to reduce token count
	// or avoid altering message content sent to providers).
	//
	// Security note: origin tags are plain-text markers prepended to message content.
	// They are trivially spoofable by any content source (users, tools) that can
	// include the same prefix string. Do NOT rely on origin tags for security
	// decisions; use the Origin field in store.Message and provider.Message instead,
	// which is set from auditable server-side context and never derived from content.
	DisableOriginTagging bool
}

// validateMode checks that a single ScannerMode field is non-empty and valid.
func validateMode(mode types.ScannerMode, name string) error {
	if mode == "" {
		return sigilerr.Errorf(sigilerr.CodeAgentLoopInvalidInput, "ScannerModes.%s is required", name)
	}
	if !mode.Valid() {
		return sigilerr.Errorf(sigilerr.CodeAgentLoopInvalidInput, "invalid ScannerModes.%s: %q", name, mode)
	}
	return nil
}

// Validate checks that all scanner mode fields are non-empty and valid.
func (m ScannerModes) Validate() error {
	if err := validateMode(m.Input, "Input"); err != nil {
		return err
	}
	if err := validateMode(m.Tool, "Tool"); err != nil {
		return err
	}
	return validateMode(m.Output, "Output")
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
// If Hooks is nil, it defaults to a zero-value LoopHooks (all hook fields nil,
// meaning no hooks fire). This is equivalent to passing &LoopHooks{}.
//
// Breaking change (PR #17): Scanner and ScannerModes are now required fields.
// Callers constructing LoopConfig via struct literals must provide both fields
// or Validate() will return an error. Use DefaultScannerModes for the
// recommended defaults, or NewScannerModesFromConfig() for config-derived modes.
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

// Validate checks that all required fields in LoopConfig are set.
// Required: SessionManager, Enforcer, ProviderRouter, Scanner (non-nil),
// and ScannerModes (all three stage modes must be valid).
func (c LoopConfig) Validate() error {
	if c.SessionManager == nil {
		return sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "SessionManager is required")
	}
	if c.Enforcer == nil {
		return sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Enforcer is required")
	}
	if c.ProviderRouter == nil {
		return sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "ProviderRouter is required")
	}
	if c.Scanner == nil {
		return sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Scanner is required")
	}
	return c.ScannerModes.Validate()
}

// Loop is the agent's core processing pipeline.
type Loop struct {
	sessions               *SessionManager
	enforcer               *security.Enforcer
	providerRouter         provider.Router
	auditStore             store.AuditStore
	toolDispatcher         *ToolDispatcher
	toolRegistry           ToolRegistry
	maxToolCallsPerTurn    int
	hooks                  *LoopHooks
	scanner                scanner.Scanner
	scannerModes           ScannerModes
	// auditFailCount tracks total audit-write failures for fail-open degradation.
	auditFailCount         atomic.Int64
	// auditSecurityFailCount tracks security-related audit-write failures separately.
	auditSecurityFailCount atomic.Int64
}

// NewLoop creates a Loop with the given dependencies.
// Required: SessionManager, Enforcer, ProviderRouter, Scanner, and ScannerModes
// (all three stage modes must be valid). Returns an error if any required
// dependency is nil or invalid.
func NewLoop(cfg LoopConfig) (*Loop, error) {
	if err := cfg.Validate(); err != nil {
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
		hooks:               orDefaultHooks(cfg.Hooks),
		scanner:             cfg.Scanner,
		scannerModes:        cfg.ScannerModes,
	}, nil
}

// ProcessMessage executes the 7-step agent pipeline:
// RECEIVE → PREPARE → CALL_LLM → PROCESS → TOOL_LOOP → RESPOND → AUDIT.
//
// Note: The security model design doc (docs/design/03-security-model.md) uses its
// own step numbering for scanner hooks (Steps 1/6/7). Those numbers reference the
// security pipeline, not this function's step sequence. Cross-reference:
//
//	design Step 1 (input scan)  = this Step 2 (PREPARE)
//	design Step 6 (tool scan)   = this Step 4 (PROCESS) / Step 5 (TOOL_LOOP)
//	design Step 7 (output scan) = this Step 6 (RESPOND)
func (l *Loop) ProcessMessage(ctx context.Context, msg InboundMessage) (*OutboundMessage, error) {
	// Step 1: RECEIVE — validate input.
	if err := l.validateInput(msg); err != nil {
		return nil, err
	}
	l.fireHook(l.hooks.OnReceive)

	// Step 2: PREPARE — load session, build message array.
	session, messages, err := l.prepare(ctx, msg)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "prepare: session %s", msg.SessionID)
	}
	l.fireHook(l.hooks.OnPrepare)

	// Step 3: CALL_LLM — route to provider and call Chat.
	eventCh, selectedProvider, err := l.callLLM(ctx, msg.WorkspaceID, session, messages)
	if err != nil {
		return nil, err
	}
	l.fireHook(l.hooks.OnCallLLM)

	// Step 4: PROCESS — buffer text deltas and collect tool calls.
	text, toolCalls, usage, streamErr := l.processEvents(eventCh)
	if streamErr != nil {
		// Drain remaining events to unblock the forwarding goroutine and prevent a leak.
		for range eventCh {
		}
	}
	l.fireHook(l.hooks.OnProcess)

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
	out, outputThreat, err := l.respond(ctx, msg.SessionID, msg.WorkspaceID, text, usage)
	if err != nil {
		if sigilerr.IsScannerCode(err) {
			slog.ErrorContext(ctx, "output scan rejected LLM response",
				slog.String("session_id", msg.SessionID),
				slog.String("workspace_id", msg.WorkspaceID),
				slog.Any("error", err),
				slog.Any("error_code", sigilerr.CodeOf(err)),
			)
			// Skip audit for context cancellation: cancellation is infrastructure,
			// not a security threat, and should not pollute audit logs.
			if !sigilerr.HasCode(err, sigilerr.CodeSecurityScannerCancelled) {
				if outputThreat == nil {
					slog.WarnContext(ctx, "auditScanBlocked called with nil ThreatInfo",
						slog.String("session_id", msg.SessionID),
						slog.Any("error", err),
					)
				}
				l.auditScanBlocked(ctx, msg, outputThreat, scanBlockedReason(outputThreat, err),
					"agent_loop.output_blocked",
					map[string]any{"stage": string(types.ScanStageOutput)})
			}
			return nil, err
		}
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "respond: session %s", msg.SessionID)
	}
	l.fireHook(l.hooks.OnRespond)

	// Step 7: AUDIT — log the interaction, including threat metadata if detected.
	l.audit(ctx, msg, out, outputThreat)
	l.fireHook(l.hooks.OnAudit)

	return out, nil
}

// orDefaultHooks returns h if non-nil, otherwise a zero-value LoopHooks.
// This ensures l.hooks is never nil so call sites can safely access fields
// like l.hooks.OnReceive without a nil-pointer check.
func orDefaultHooks(h *LoopHooks) *LoopHooks {
	if h != nil {
		return h
	}
	return &LoopHooks{}
}

func (l *Loop) fireHook(fn func()) {
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
	scanned, inputThreat, scanErr := l.scanContent(ctx, msg.Content, scanRequest{
		stage:       types.ScanStageInput,
		origin:      types.OriginUserInput,
		mode:        l.scannerModes.Input,
		sessionID:   msg.SessionID,
		workspaceID: msg.WorkspaceID,
	})
	if scanErr != nil {
		// Audit blocked input before returning the error so security teams
		// have visibility into rejected messages. Determine the reason from
		// the error code so auditors can distinguish infrastructure failures
		// from actual threat detections.
		auditReason := scanBlockedReason(inputThreat, scanErr)
		switch auditReason {
		case "scanner_failure", "content_too_large":
			slog.ErrorContext(ctx, "input rejected by scanner",
				slog.String("reason", auditReason),
				slog.Any("error", scanErr),
				slog.String("session_id", msg.SessionID),
				slog.String("workspace_id", msg.WorkspaceID),
			)
		case "blocked_threat":
			slog.WarnContext(ctx, "input scan blocked threat",
				slog.String("reason", auditReason),
				slog.String("session_id", msg.SessionID),
				slog.String("workspace_id", msg.WorkspaceID),
			)
		}
		// Skip audit for context cancellation: cancellation is infrastructure,
		// not a security threat, and should not pollute audit logs.
		if !sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerCancelled) {
			l.auditScanBlocked(ctx, msg, inputThreat, auditReason,
				"agent_loop.input_blocked",
				map[string]any{"content_length": len(msg.Content)})
		}
		return nil, nil, scanErr
	}
	// Log a SHA-256 hash of the original content at DEBUG level for forensic
	// traceability before replacing it with the normalized form. This allows
	// security teams to correlate normalized content back to the original
	// input without persisting the raw user data.
	slog.DebugContext(ctx, "input content normalized",
		"original_sha256", contentHashPrefix(msg.Content),
		"session_id", msg.SessionID,
		"workspace_id", msg.WorkspaceID,
	)
	// Note: msg.Content is replaced with the scanner-normalized form.
	// scanner.Normalize applies HTML entity decoding, zero-width character
	// stripping, and NFKC normalization. The normalized content is persisted,
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
		Origin:    string(types.OriginUserInput),
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
		origin := types.Origin(m.Origin)
		if !origin.Valid() {
			slog.WarnContext(ctx, "message has invalid origin, falling back to role-derived",
				slog.String("message_id", m.ID),
				slog.String("stored_origin", m.Origin),
				slog.String("role", string(m.Role)),
				slog.String("session_id", msg.SessionID),
			)
			origin = originFromRole(m.Role)
		}
		messages = append(messages, provider.Message{
			Role:       m.Role,
			Content:    m.Content,
			ToolCallID: m.ToolCallID,
			ToolName:   m.ToolName,
			Origin:     origin,
		})
	}

	return session, messages, nil
}

// callLLM calls the provider route with failover support. Failover only covers
// first-event failures (auth errors, rate limits, provider down). Mid-stream
// failures are not retried because replaying the full conversation to a fallback
// provider requires buffering all events and resending all messages — significant
// complexity with partial-output ambiguity. Mid-stream errors surface to the caller
// via processEvents. See D036 (docs/decisions/decision-log.md) for design rationale.
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
			providerFailures = append(providerFailures, fmt.Sprintf("route attempt %d: %s", attempt+1, err.Error()))
			continue
		}

		triedProviders = append(triedProviders, prov.Name())

		req := provider.ChatRequest{
			Model:        resolvedModel,
			Messages:     messages,
			SystemPrompt: defaultSystemPrompt,
			Options:      provider.ChatOptions{Stream: true, OriginTagging: !l.scannerModes.DisableOriginTagging},
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
			lastErr = sigilerr.With(sigilerr.Wrapf(err, sigilerr.CodeProviderUpstreamFailure, "chat call to %s", prov.Name()), sigilerr.FieldProvider(prov.Name()))
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
			lastErr = sigilerr.With(sigilerr.Errorf(sigilerr.CodeProviderUpstreamFailure, "provider %s: stream closed without events", prov.Name()), sigilerr.FieldProvider(prov.Name()))
			providerFailures = append(providerFailures, fmt.Sprintf("%s: stream closed without events", prov.Name()))
			continue
		}

		if firstEvent.Type == provider.EventTypeError {
			l.recordProviderFailure(prov)
			lastErr = sigilerr.With(sigilerr.Errorf(sigilerr.CodeProviderUpstreamFailure, "provider %s: %s", prov.Name(), firstEvent.Error), sigilerr.FieldProvider(prov.Name()))
			providerFailures = append(providerFailures, fmt.Sprintf("%s: %s", prov.Name(), firstEvent.Error))
			l.drainEventChannel(eventCh)
			continue
		}

		// First event is valid — wrap it back with the rest of the stream.
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

	// All providers failed. Build a combined error message for observability.
	// For a single provider failure with a specific error code, preserve that code.
	// For routing-only failures or multiple failures, use CodeProviderAllUnavailable.
	if len(providerFailures) > 0 {
		combinedMsg := fmt.Sprintf("all providers failed for workspace %s: %s", workspaceID, strings.Join(providerFailures, "; "))
		code := sigilerr.CodeOf(lastErr)
		if len(providerFailures) == 1 && code != "" {
			return nil, nil, sigilerr.Errorf(code, "%s", combinedMsg)
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
	// scannerFailCount is a per-turn local counter for the scanner circuit
	// breaker. It is local (not a Loop field) so that concurrent
	// ProcessMessage calls do not share state. See D062 and sigil-7g5.595
	// for rationale.
	var scannerFailCount int

	currentMessages := make([]provider.Message, len(messages))
	copy(currentMessages, messages)
	currentToolCalls := toolCalls
	text := initialText
	var usage *provider.Usage

	for i := range maxToolLoopIterations {
		// If the LLM emitted text alongside tool calls, persist it as an
		// assistant message so the conversation history stays coherent.
		if text != "" {
			// Output scanning — filter secrets from intermediate assistant text
			// before persisting to session history.
			scannedText, intermediateThreat, scanErr := l.scanContent(ctx, text, scanRequest{
				stage:       types.ScanStageOutput,
				origin:      types.OriginSystem,
				mode:        l.scannerModes.Output,
				sessionID:   msg.SessionID,
				workspaceID: msg.WorkspaceID,
			})
			if scanErr != nil {
				// Scanner failure logged at Error; no external alerting integration (Sentry/PD) exists yet.
				slog.ErrorContext(ctx, "intermediate output scan failed in tool loop",
					slog.String("session_id", msg.SessionID),
					slog.String("workspace_id", msg.WorkspaceID),
					slog.Int("tool_iteration", i),
					slog.Any("error", scanErr),
					slog.Any("error_code", sigilerr.CodeOf(scanErr)),
				)
				l.auditScanBlocked(ctx, msg, intermediateThreat, scanBlockedReason(intermediateThreat, scanErr),
				"agent_loop.output_blocked",
				map[string]any{"stage": string(types.ScanStageOutput)})
				return "", nil, scanErr
			}
			text = scannedText

			assistantMsg := &store.Message{
				ID:        uuid.New().String(),
				SessionID: msg.SessionID,
				Role:      store.MessageRoleAssistant,
				Content:   text,
				Origin:    string(types.OriginSystem),
				Threat:    intermediateThreat,
				CreatedAt: time.Now(),
			}
			if err := l.sessions.AppendMessage(ctx, msg.SessionID, assistantMsg); err != nil {
				return "", nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "persisting assistant message: session %s", msg.SessionID)
			}
			currentMessages = append(currentMessages, provider.Message{
				Role:    store.MessageRoleAssistant,
				Content: text,
				Origin:  types.OriginSystem,
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
				resultContent = l.sanitizeToolError(ctx, err, tc.Name, pluginName, msg.SessionID, msg.WorkspaceID)
			} else {
				resultContent = result.Content
			}

			// Tool result scanning — check for instruction injection before persisting.
			scannedResult, toolThreat, scanErr := l.scanContent(ctx, resultContent, scanRequest{
				stage:            types.ScanStageTool,
				origin:           types.OriginToolOutput,
				mode:             l.scannerModes.Tool,
				sessionID:        msg.SessionID,
				workspaceID:      msg.WorkspaceID,
				scannerFailCount: &scannerFailCount,
			})

			// Audit tool-stage threat detections and scanner bypasses.
			// Called before the error check so blocked threats still have an audit trail.
			l.auditToolScan(ctx, msg, tc.ID, tc.Name, toolThreat, scanErr)

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
				Origin:     string(types.OriginToolOutput),
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
				Origin:     types.OriginToolOutput,
			})
		}

		// Re-call the LLM with updated message history.
		eventCh, toolLoopProvider, err := l.callLLM(ctx, msg.WorkspaceID, session, currentMessages)
		if err != nil {
			return "", nil, err
		}

		var streamErr error
		text, currentToolCalls, usage, streamErr = l.processEvents(eventCh)
		if streamErr != nil {
			// Drain remaining events to unblock the forwarding goroutine and prevent a leak.
			for range eventCh {
			}
		}

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

func (l *Loop) respond(ctx context.Context, sessionID, workspaceID, text string, usage *provider.Usage) (*OutboundMessage, *store.ThreatInfo, error) {
	// Output scanning — filter secrets before persisting/returning.
	scanned, outputThreat, scanErr := l.scanContent(ctx, text, scanRequest{
		stage:       types.ScanStageOutput,
		origin:      types.OriginSystem,
		mode:        l.scannerModes.Output,
		sessionID:   sessionID,
		workspaceID: workspaceID,
	})
	if scanErr != nil {
		return nil, outputThreat, scanErr
	}
	text = scanned

	// Persist the assistant response.
	assistantMsg := &store.Message{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		Role:      store.MessageRoleAssistant,
		Content:   text,
		Origin:    string(types.OriginSystem),
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

func originFromRole(role store.MessageRole) types.Origin {
	switch role {
	case store.MessageRoleUser:
		return types.OriginUserInput
	case store.MessageRoleTool:
		return types.OriginToolOutput
	default:
		return types.OriginSystem
	}
}

func (l *Loop) audit(ctx context.Context, msg InboundMessage, out *OutboundMessage, threatInfo *store.ThreatInfo) {
	if l.auditStore == nil {
		return
	}

	details := map[string]any{"content_length": len(out.Content)}

	// Include threat metadata in audit details when threats were detected.
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
	// Design tension: the security principle "MUST audit security-relevant operations"
	// conflicts with availability here. D062 accepts this tradeoff: a failed audit
	// log should not block the user response. Consecutive failures escalate log level
	// (warn → error) to ensure operator visibility without impacting availability.
	l.appendAuditEntry(ctx, entry, &l.auditFailCount, "audit store append failed",
		slog.String("workspace_id", msg.WorkspaceID), slog.String("session_id", msg.SessionID))
}

// scanBlockedReason derives a human-readable audit reason string from a scanner
// error and optional threat info. The returned value disambiguates blocked audit
// entries so security teams can distinguish real threat detections from
// infrastructure failures:
//   - "blocked_threat"      — scanner detected a threat and blocked the content
//   - "scanner_failure"     — scanner returned an infrastructure error
//   - "content_too_large"   — content exceeded the scanner size limit
//   - "circuit_breaker_open" — scanner circuit breaker is open
func scanBlockedReason(threatInfo *store.ThreatInfo, scanErr error) string {
	switch {
	case sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerCircuitBreakerOpen):
		return "circuit_breaker_open"
	case sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerContentTooLarge):
		return "content_too_large"
	case threatInfo != nil && threatInfo.Detected:
		return "blocked_threat"
	default:
		return "scanner_failure"
	}
}

// buildBlockedAuditEntry constructs a *store.AuditEntry for a blocked input or
// output scan event. The action parameter selects the audit action name
// (e.g. "agent_loop.input_blocked"). extraDetails keys are merged into the
// entry's Details map after the standard threat fields are populated; callers
// use this to add stage-specific fields (e.g. "stage").
func buildBlockedAuditEntry(action string, msg InboundMessage, threatInfo *store.ThreatInfo, reason string, extraDetails map[string]any) *store.AuditEntry {
	details := make(map[string]any, len(extraDetails)+3)
	for k, v := range extraDetails {
		details[k] = v
	}
	if threatInfo == nil {
		details["scanner_error"] = true
	} else if threatInfo.Detected {
		details["threat_detected"] = true
		details["threat_rules"] = threatInfo.Rules
		details["threat_stage"] = string(threatInfo.Stage)
	}

	// Derive the Result value from reason so auditors can distinguish
	// real threat detections from infrastructure failures.
	result := reason
	if result == "" {
		result = "blocked"
	}

	return &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      action,
		Actor:       msg.UserID,
		WorkspaceID: msg.WorkspaceID,
		SessionID:   msg.SessionID,
		Details:     details,
		Result:      result,
	}
}

// auditScanBlocked records a best-effort audit entry when the input or output
// scanner blocks a message. This gives security teams visibility into rejected
// content without failing the already-failing request path.
//
// The reason parameter disambiguates the audit Result:
//   - "blocked_threat"    — scanner detected a threat and blocked the message
//   - "scanner_failure"   — scanner returned an infrastructure error
//   - "content_too_large" — message exceeded the scanner size limit
//
// action and extraDetails distinguish input vs. output scan paths.
func (l *Loop) auditScanBlocked(ctx context.Context, msg InboundMessage, threatInfo *store.ThreatInfo, reason string, action string, extraDetails map[string]any) {
	if l.auditStore == nil {
		return
	}
	logMsg := "audit store append failed for " + action
	entry := buildBlockedAuditEntry(action, msg, threatInfo, reason, extraDetails)
	l.appendAuditEntry(ctx, entry, &l.auditSecurityFailCount, logMsg,
		slog.String("workspace_id", msg.WorkspaceID), slog.String("session_id", msg.SessionID))
}

// auditToolScan records best-effort audit entries for tool-stage security events:
// threat detections (mode=flag, Detected=true) and scanner bypasses (Bypassed=true).
// Entries are omitted when auditStore is nil, when threatInfo is nil (scanner returned
// no result), or when threatInfo indicates neither a detection nor a bypass (clean scan).
func (l *Loop) auditToolScan(ctx context.Context, msg InboundMessage, toolCallID, toolName string, threatInfo *store.ThreatInfo, scanErr error) {
	if l.auditStore == nil {
		return
	}
	// Skip when scan succeeded and no threat was detected or bypassed.
	if scanErr == nil && (threatInfo == nil || (!threatInfo.Detected && !threatInfo.Bypassed)) {
		return
	}

	var action string
	details := map[string]any{
		"tool_call_id": toolCallID,
		"tool_name":    toolName,
	}

	if threatInfo != nil {
		details["stage"] = string(threatInfo.Stage)
		if threatInfo.Bypassed {
			action = "agent_loop.tool_scan_bypassed"
			details["bypassed"] = true
		} else {
			action = "agent_loop.tool_scan_threat"
			details["threat_detected"] = true
			details["threat_rules"] = threatInfo.Rules
		}
	} else {
		// Defensive: handleToolScanFailure always returns non-nil ThreatInfo,
		// so this branch should be unreachable. Log if the invariant breaks.
		slog.WarnContext(ctx, "auditToolScan: unexpected nil threatInfo with scan error",
			slog.String("tool_call_id", toolCallID),
			slog.String("tool_name", toolName),
			slog.Any("error", scanErr),
		)
		action = "agent_loop.tool_scan_error"
	}

	result := "ok"
	if threatInfo == nil && scanErr != nil {
		// Defensive nil-threatInfo branch: the invariant that handleToolScanFailure
		// always returns non-nil ThreatInfo was violated. Record as scan_error to
		// distinguish this from a normal bypass (where ThreatInfo is always set).
		result = "scan_error"
		details["scan_error"] = scanErr.Error()
		details["error_code"] = string(sigilerr.CodeOf(scanErr))
	} else if scanErr != nil {
		// Content was not blocked — it was passed through unscanned (bypassed).
		// Use "bypassed" rather than "blocked" to accurately reflect the outcome.
		result = "bypassed"
		details["scan_error"] = scanErr.Error()
		details["error_code"] = string(sigilerr.CodeOf(scanErr))
	} else if threatInfo != nil && threatInfo.Bypassed {
		// Scan succeeded but was bypassed (best-effort path) — still unscanned.
		result = "bypassed"
	}

	entry := &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      action,
		Actor:       msg.UserID,
		WorkspaceID: msg.WorkspaceID,
		SessionID:   msg.SessionID,
		Details:     details,
		Result:      result,
	}

	l.appendAuditEntry(ctx, entry, &l.auditSecurityFailCount, "audit store append failed for tool scan",
		slog.String("workspace_id", msg.WorkspaceID), slog.String("session_id", msg.SessionID), slog.String("tool_call_id", toolCallID))
}

// appendAuditEntry is the shared append+counter+escalation pattern used by
// audit(), auditScanBlocked(), and auditToolScan(). On success it resets
// the counter; on failure it increments and logs at an escalating level.
func (l *Loop) appendAuditEntry(ctx context.Context, entry *store.AuditEntry, counter *atomic.Int64, logMsg string, attrs ...slog.Attr) {
	if err := l.auditStore.Append(ctx, entry); err != nil {
		consecutive := counter.Add(1)
		extra := append(attrs,
			slog.Any("error", err),
			slog.Int64("consecutive_failures", consecutive),
		)
		logAuditFailure(ctx, consecutive, logMsg, extra...)
	} else {
		counter.Store(0)
	}
}

// auditLogEscalationThreshold and logAuditFailure are defined in audit.go
// so they can be shared between Loop and ToolDispatcher.

// scanRequest bundles the per-invocation parameters for scanContent and
// scanOversizedToolContent, reducing parameter count and preventing
// parameter-order mistakes.
type scanRequest struct {
	stage            types.ScanStage
	origin           types.Origin
	mode             types.ScannerMode
	sessionID        string
	workspaceID      string
	scannerFailCount *int // nil for non-tool stages
}

// maxToolContentScanSize is the truncation limit applied to oversized tool results
// before re-scanning. A malicious tool could return content larger than the scanner's
// maximum (1MB) to trigger a content_too_large error and bypass scanning. Truncating
// to 512KB and re-scanning closes that bypass while still scanning the leading content
// where prompt-injection payloads are most likely to appear.
const maxToolContentScanSize = 512 * 1024 // 512KB

// scannerCircuitBreakerThreshold is the number of per-turn total tool-stage scanner
// failures after which the best-effort path switches to fail-closed. Once this
// threshold is reached, tool results are blocked instead of passed through
// unscanned. The counter (scannerFailCount) is a local variable in runToolLoop.
const scannerCircuitBreakerThreshold = 3

// truncationMarker is appended to tool results that were truncated before re-scanning
// so the LLM is explicitly informed that the data was cut and may be incomplete.
const truncationMarker = "\n\n[TRUNCATED: tool result exceeded scan limit]"

// scanContent scans content at the given stage and applies the configured mode.
// Returns the (possibly redacted) content, threat info (if a threat was detected), or an error
// if scanning fails or the mode blocks. Scanner is guaranteed non-nil by NewLoop validation.
//
// The scanner internally applies normalization via scanner.Normalize: HTML entity decoding,
// zero-width character stripping, and NFKC normalization. Callers receive the normalized
// form; normalization is not performed separately at this level.
//
// For StageTool, scanner internal errors are handled best-effort up to a threshold: normalized
// content is returned without rule evaluation on each failure below the limit. Once
// scannerCircuitBreakerThreshold per-turn total failures are reached, a circuit-breaker trips
// and tool results are blocked (fail-closed) instead of passed through unscanned.
// req.scannerFailCount is the per-turn local counter (nil for non-tool stages). See D062 for rationale.
//
// Cancellation contract: when the context is cancelled, scanContent returns ("", nil, err) where
// err carries CodeSecurityScannerCancelled. ThreatInfo is nil in this case — callers MUST check
// for CodeSecurityScannerCancelled (via sigilerr.HasCode) before dereferencing the ThreatInfo
// pointer, and MUST NOT treat a nil ThreatInfo as "no threat detected".
func (l *Loop) scanContent(ctx context.Context, content string, req scanRequest) (string, *store.ThreatInfo, error) {
	log := slog.With(slog.String("session_id", req.sessionID), slog.String("workspace_id", req.workspaceID))
	scanResult, scanErr := l.scanner.Scan(ctx, content, scanner.NewScanContext(req.stage, req.origin, map[string]string{
		"session_id":   req.sessionID,
		"workspace_id": req.workspaceID,
	}))
	if scanErr != nil {
		// ── Category 1: Cancellation — always fail-closed (all stages) ──────────────
		// Context cancellation is handled first since it applies uniformly to all
		// stages and should not be confused with infrastructure failures. The
		// dedicated error code (CodeSecurityScannerCancelled) allows callers to
		// distinguish cancellation from scanner malfunctions.
		if sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerCancelled) {
			log.LogAttrs(ctx, slog.LevelInfo, "scan cancelled by context",
				slog.String("stage", string(req.stage)),
				slog.Any("error", scanErr),
			)
			// Nil-ThreatInfo cancellation path: returns ("", nil, err) with
			// CodeSecurityScannerCancelled. ThreatInfo is nil here — it does NOT
			// mean "no threat". Callers must guard on sigilerr.HasCode before use.
			return "", nil, sigilerr.Wrapf(scanErr, sigilerr.CodeSecurityScannerCancelled,
				"scanning %s content cancelled", req.stage)
		}

		// ── Configuration error: empty rule stage ────────────────────────────────
		// Checked before stage-specific handling so operators get a clear signal
		// that the scanner is misconfigured rather than a generic malfunction.
		if sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerEmptyRuleStage) {
			slog.ErrorContext(ctx, "scanner configuration error: stage has no rules",
				slog.String("stage", string(req.stage)),
				slog.String("session_id", req.sessionID),
				slog.String("workspace_id", req.workspaceID),
			)
			return "", nil, sigilerr.Wrapf(scanErr, sigilerr.CodeSecurityScannerEmptyRuleStage,
				"scanning %s content: no rules configured for stage", req.stage)
		}

		// ── Tool stage: delegate all non-cancellation errors to handleToolScanError ──
		// Tool stage has "best-effort" semantics (D062): ContentTooLarge truncates and
		// re-scans, generic errors pass through normalized content up to the circuit-
		// breaker threshold. Input/output stages are handled below (fail-closed).
		if req.stage == types.ScanStageTool {
			if sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerContentTooLarge) {
				return l.scanOversizedToolContent(ctx, content, req, scanErr, log)
			}
			// Generic scanner error: apply best-effort circuit-breaker logic.
			// D062: availability over security for tool results below the threshold.
			return l.handleToolScanFailure(ctx, content, scanErr, req.stage, req.scannerFailCount, log)
		}

		// ── Categories 2 & 3: Input/Output stages — fail-closed ───────────────────
		// Scanner failure logged at Error; no external alerting integration (Sentry/PD) exists yet.
		msg := "scanner failure on " + string(req.stage) + " content"
		attrs := []slog.Attr{slog.Any("error", scanErr), slog.String("stage", string(req.stage))}
		if sigilerr.HasCode(scanErr, sigilerr.CodeSecurityScannerContentTooLarge) {
			msg = "content exceeds scanner limit"
			attrs = append(attrs, slog.Int("content_length", len(content)))
		}
		log.LogAttrs(ctx, slog.LevelError, msg, attrs...)
		return "", nil, sigilerr.Wrapf(scanErr, sigilerr.CodeOf(scanErr),
			"scanning %s content", req.stage)
	}

	return l.applyScannedResult(ctx, req.stage, req.mode, scanResult, log)
}

// scanOversizedToolContent handles the content_too_large error path for tool-stage scans.
// A malicious tool could return >1MB content to trigger a content_too_large error and
// bypass scanning (sigil-7g5.184). This helper truncates to maxToolContentScanSize and
// re-scans the truncated content. If the re-scan succeeds, the result is returned with a
// truncation marker appended. If the re-scan also returns content_too_large (scanner
// limit < maxToolContentScanSize), scannerFailCount is incremented (unscanned content is
// the same outcome regardless of cause) and the function returns normalized content
// unscanned. If the re-scan fails with any other error, the call falls through to the
// generic best-effort path (increment scannerFailCount, log, and either circuit-break or
// return normalized content).
func (l *Loop) scanOversizedToolContent(ctx context.Context, content string, req scanRequest, primaryScanErr error, log *slog.Logger) (string, *store.ThreatInfo, error) {
	// Truncate to strictly below the scanner limit so the re-scan cannot hit
	// content_too_large again on the raw bytes (normalization expansion may
	// still cause a double-failure, which is handled below).
	n := min(len(content), maxToolContentScanSize-1)
	// Walk backwards to find a valid UTF-8 rune boundary so we do not
	// split a multi-byte codepoint (sigil-7g5.273).
	for n > 0 && n < len(content) && !utf8.RuneStart(content[n]) {
		n--
	}
	truncated := content[:n]
	log.LogAttrs(ctx, slog.LevelWarn, "tool result exceeds scanner limit, truncating and re-scanning",
		slog.Int("original_size", len(content)),
		slog.Int("truncated_size", len(truncated)),
		slog.Any("stage", req.stage),
	)
	reScanResult, reScanErr := l.scanner.Scan(ctx, truncated, scanner.NewScanContext(req.stage, req.origin, map[string]string{
		"session_id":   req.sessionID,
		"workspace_id": req.workspaceID,
	}))
	if reScanErr == nil {
		// Re-scan succeeded: apply mode against the truncated+scanned result,
		// then append a truncation marker so the LLM is informed the result was cut.
		result, threatInfo, applyErr := l.applyScannedResult(ctx, req.stage, req.mode, reScanResult, log)
		if applyErr != nil {
			return "", threatInfo, sigilerr.Wrapf(applyErr, sigilerr.CodeSecurityScannerToolBlocked,
				"tool result truncated from %d to %d bytes before scanning", len(content), len(truncated))
		}
		log.Log(ctx, slog.LevelWarn, "tool result truncated for scanning")
		return result + truncationMarker, threatInfo, nil
	}

	// Re-scan also returned content_too_large: the scanner limit is smaller
	// than maxToolContentScanSize. This is a configuration mismatch, but we
	// still count toward the circuit breaker — unscanned content is the same
	// outcome regardless of cause, and repeated mismatches should trip the
	// threshold (3) to alert operators.
	if sigilerr.HasCode(reScanErr, sigilerr.CodeSecurityScannerContentTooLarge) {
		*req.scannerFailCount++
		log.LogAttrs(ctx, slog.LevelError, "truncated tool result still exceeds scanner limit, passing normalized content unscanned",
			slog.Int("original_size", len(content)),
			slog.Int("truncated_size", len(truncated)),
			slog.Any("stage", req.stage),
			slog.String("error_code", string(sigilerr.CodeSecurityScannerContentTooLarge)),
		)
		return scanner.Normalize(truncated), store.NewBypassedScan(store.ScanStageTool), nil
	}

	// Re-scan also failed: delegate to handleToolScanFailure for circuit-breaker
	// escalation. Log both errors so operators can distinguish a double-failure from a
	// single internal scanner failure (sigil-7g5.279). Both the primary scan
	// error and the re-scan error are included as structured attrs (sigil-7g5.588).
	result, threat, err := l.handleToolScanFailure(ctx, truncated, reScanErr, req.stage, req.scannerFailCount,
		log.With(
			slog.String("primary_scan_error", primaryScanErr.Error()),
			slog.String("primary_scan_error_code", string(sigilerr.CodeOf(primaryScanErr))),
			slog.String("re_scan_error", reScanErr.Error()),
		),
	)
	// Append the truncation marker so the LLM is informed that the content was
	// cut. On the success path (re-scan succeeds) this marker is already added
	// (sigil-7g5.798); without it here the LLM would silently receive truncated
	// content with no indication it was incomplete.
	if result != "" {
		result += truncationMarker
	}
	return result, threat, err
}

// handleToolScanFailure centralises the circuit-breaker escalation logic shared
// between scanContent (generic scanner error on tool stage) and
// scanOversizedToolContent (double-failure after truncated re-scan). It:
//  1. Increments *scannerFailCount and captures the new count.
//  2. Selects log level: Warn below scannerCircuitBreakerThreshold, Error at/above.
//  3. Computes a SHA-256 content hash over scanner.Normalize(content) for forensic
//     correlation when content passes through unscanned.
//  4. Emits a structured log entry with standard attrs merged with any pre-attached log fields.
//  5. If the threshold is reached, returns a non-nil bypass ThreatInfo alongside a
//     circuit-breaker error (fail-closed). The non-nil ThreatInfo ensures auditToolScan
//     records an audit entry even on the blocked circuit-breaker path.
//  6. Otherwise returns scanner.Normalize(content) with a bypass ThreatInfo marker
//     so audit queries can distinguish "unscanned" from "scanned clean". The SHA-256
//     hash is over the normalized content (not scanner.Name or any scanner identifier).
func (l *Loop) handleToolScanFailure(ctx context.Context, content string, scanErr error, stage types.ScanStage, scannerFailCount *int, log *slog.Logger) (string, *store.ThreatInfo, error) {
	if scannerFailCount == nil {
		panic("scannerFailCount must not be nil for tool stage")
	}
	*scannerFailCount++
	count := *scannerFailCount
	logLevel := slog.LevelWarn
	if count >= scannerCircuitBreakerThreshold {
		logLevel = slog.LevelError
	}
	// Content hash (first 16 hex chars of SHA-256) for forensic
	// correlation when content passes through unscanned.
	normalized := scanner.Normalize(content)
	contentHash := contentHashPrefix(normalized)
	log.LogAttrs(ctx, logLevel, "scanner internal error on tool result",
		slog.Any("error", scanErr),
		slog.Any("stage", stage),
		slog.Any("error_code", sigilerr.CodeOf(scanErr)),
		slog.Int("per_turn_failures", count),
		slog.String("content_hash", contentHash),
	)

	// Circuit breaker: after scannerCircuitBreakerThreshold per-turn total
	// failures, switch from best-effort (pass through) to fail-closed
	// (block the content). Counter is per-turn only (local to runToolLoop)
	// so a tool alternating clean/malicious results cannot avoid the
	// threshold by interleaving successes.
	if count >= scannerCircuitBreakerThreshold {
		// Return a non-nil bypass ThreatInfo so auditToolScan produces an audit
		// entry for the circuit-breaker trip (sigil-7g5.612). Without this,
		// the nil guard in auditToolScan silently drops the audit entry.
		return "", store.NewBypassedScan(stage), sigilerr.Errorf(
			sigilerr.CodeSecurityScannerCircuitBreakerOpen,
			"scanner circuit breaker open: %d per-turn tool-stage failures (threshold %d)",
			count, scannerCircuitBreakerThreshold,
		)
	}

	return normalized, store.NewBypassedScan(stage), nil
}

// collectMatchRules iterates scan matches, extracts rule names, tracks the highest
// severity, and emits per-match debug logs. Returns the collected rules and the
// highest severity found (empty if no matches).
func collectMatchRules(ctx context.Context, log *slog.Logger, stage types.ScanStage, mode types.ScannerMode, matches []scanner.Match) ([]string, scanner.Severity) {
	rules := make([]string, 0, len(matches))
	highestSeverity := scanner.Severity("")
	for _, m := range matches {
		rules = append(rules, m.Rule)
		if highestSeverity == "" || m.Severity.Rank() > highestSeverity.Rank() {
			highestSeverity = m.Severity
		}
		log.LogAttrs(ctx, slog.LevelDebug, "security scan match detail",
			slog.String("rule", m.Rule),
			slog.Any("severity", m.Severity),
			slog.Any("stage", stage),
			slog.String("scanner_mode", string(mode)),
		)
	}
	return rules, highestSeverity
}

// logThreatDetection emits a warn-level log for a threat detection. Flag mode gets
// enhanced logging with content hash and highest severity; other modes get a
// consolidated summary.
func logThreatDetection(ctx context.Context, log *slog.Logger, mode types.ScannerMode, stage types.ScanStage, highestSeverity scanner.Severity, scanResult scanner.ScanResult) {
	if mode == types.ScannerModeFlag {
		log.LogAttrs(ctx, slog.LevelWarn, "scanner flag mode: threats detected in content",
			slog.Int("match_count", len(scanResult.Matches)),
			slog.String("highest_severity", string(highestSeverity)),
			slog.String("scanner_mode", string(mode)),
			slog.Any("stage", stage),
			slog.String("content_hash", contentHashPrefix(scanResult.Content)),
		)
	} else {
		log.LogAttrs(ctx, slog.LevelWarn, "scan detected threat, continuing",
			slog.Any("stage", stage),
			slog.String("mode", string(mode)),
			slog.Int("match_count", len(scanResult.Matches)),
		)
	}
}

// applyScannedResult processes a successful ScanResult: builds threat info, applies
// the configured mode, and returns the (possibly redacted) content. The per-turn
// scanner failure counter (scannerFailCount in runToolLoop) is not touched here;
// it is only incremented on failure paths via handleToolScanFailure.
//
// When ApplyMode returns an error (block mode detected a threat), threat is returned
// alongside the error. This is intentional: callers such as auditScanBlocked need
// the populated ThreatInfo to record what was blocked in the audit log.
func (l *Loop) applyScannedResult(ctx context.Context, stage types.ScanStage, mode types.ScannerMode, scanResult scanner.ScanResult, log *slog.Logger) (string, *store.ThreatInfo, error) {
	var threat *store.ThreatInfo
	if scanResult.Threat {
		rules, highestSeverity := collectMatchRules(ctx, log, stage, mode, scanResult.Matches)
		threat = store.NewThreatDetected(stage, rules)
		logThreatDetection(ctx, log, mode, stage, highestSeverity, scanResult)
	} else {
		threat = store.NewCleanScan(stage)
	}

	scanned, modeErr := scanner.ApplyMode(mode, stage, scanResult)
	if modeErr != nil {
		// Return threat alongside modeErr so callers can use ThreatInfo for audit
		// logging even on the error path (e.g., auditScanBlocked needs threat details).
		return "", threat, modeErr
	}

	return scanned, threat, nil
}


// AuditFailCount returns the current consecutive audit failure count for the
// general interaction audit(). Exposed for testing to verify best-effort audit
// semantics. This counter is independent of AuditSecurityFailCount so that
// general-audit noise does not mask security-scan escalation.
func (l *Loop) AuditFailCount() int64 {
	return l.auditFailCount.Load()
}

// AuditSecurityFailCount returns the current consecutive audit failure count
// for all security-scan audit paths (auditScanBlocked, auditToolScan). These
// paths share a single counter because they all guard the same security boundary;
// a persistent failure in any one of them is equally significant for escalation
// purposes. This counter is independent of AuditFailCount so that security-scan
// failures do not contaminate the escalation threshold for general interaction audits.
// Exposed for testing to verify best-effort audit semantics.
func (l *Loop) AuditSecurityFailCount() int64 {
	return l.auditSecurityFailCount.Load()
}

// sanitizeToolError returns a user-friendly error message for tool dispatch failures,
// avoiding leakage of internal paths, stack traces, or DB details to the LLM.
// Capability denial errors are logged at Error level (security-relevant); all others at Warn.
func (l *Loop) sanitizeToolError(ctx context.Context, err error, toolName, pluginName, sessionID, workspaceID string) string {
	code := sigilerr.CodeOf(err)

	// Capability denials are security-relevant: a plugin attempting to invoke a
	// capability it was not granted is a signal of misconfiguration or privilege
	// escalation. Log at Error to ensure visibility in security monitoring.
	level := slog.LevelWarn
	if code == sigilerr.CodePluginCapabilityDenied || code == sigilerr.CodeWorkspaceMembershipDenied {
		level = slog.LevelError
	}

	slog.Log(ctx, level, "tool dispatch error",
		"error", err,
		slog.String("tool", toolName),
		slog.String("plugin", pluginName),
		slog.String("session_id", sessionID),
		slog.String("workspace_id", workspaceID),
	)

	switch code {
	case sigilerr.CodePluginNotFound:
		return "tool not found"
	case sigilerr.CodeAgentToolBudgetExceeded:
		return "tool call limit reached"
	case sigilerr.CodeAgentToolTimeout:
		return "tool execution timed out"
	case sigilerr.CodePluginCapabilityDenied, sigilerr.CodeWorkspaceMembershipDenied:
		return "capability denied"
	}
	return "tool execution failed"
}

// contentHashPrefix returns the first 16 hex chars of the SHA-256 of s,
// sufficient for forensic log correlation without persisting raw content.
func contentHashPrefix(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// defaultMaxToolCallsPerTurn is the default maximum number of tool calls
// allowed in a single turn when MaxToolCallsPerTurn is not configured.
const defaultMaxToolCallsPerTurn = 10

// maxToolLoopIterations is the maximum number of tool-loop iterations
// (LLM call → tool dispatch → re-call) before the loop is terminated.
const maxToolLoopIterations = 5

// InboundMessage is the input to the agent loop.
type InboundMessage struct {
	SessionID   string
	WorkspaceID string
	UserID      string
	Content     string
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
	SessionManager     *SessionManager
	Enforcer           *security.Enforcer
	ProviderRouter     provider.Router
	AuditStore         store.AuditStore
	ToolDispatcher     *ToolDispatcher
	MaxToolCallsPerTurn int
	Hooks              *LoopHooks
}

// Loop is the agent's core processing pipeline.
type Loop struct {
	sessions            *SessionManager
	enforcer            *security.Enforcer
	providerRouter      provider.Router
	auditStore          store.AuditStore
	toolDispatcher      *ToolDispatcher
	maxToolCallsPerTurn int
	hooks               *LoopHooks
}

// NewLoop creates a Loop with the given dependencies.
func NewLoop(cfg LoopConfig) *Loop {
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
		maxToolCallsPerTurn: maxCalls,
		hooks:               cfg.Hooks,
	}
}

// ProcessMessage executes the 6-step agent pipeline:
// RECEIVE → PREPARE → CALL_LLM → PROCESS → RESPOND → AUDIT.
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
	eventCh, err := l.callLLM(ctx, msg.WorkspaceID, session, messages)
	if err != nil {
		return nil, err
	}
	l.fireHook(l.hooks, hookCallLLM)

	// Step 4: PROCESS — buffer text deltas and collect tool calls.
	text, toolCalls, usage, streamErr := l.processEvents(eventCh)
	l.fireHook(l.hooks, hookProcess)

	// If the stream emitted a fatal error, discard partial output and fail the turn.
	if streamErr != nil {
		return nil, sigilerr.Wrapf(streamErr, sigilerr.CodeProviderUpstreamFailure, "stream error: session %s", msg.SessionID)
	}

	// Step 4b: TOOL LOOP — dispatch tool calls and re-call the LLM.
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

	// Step 5: RESPOND — build outbound message, persist assistant message.
	out, err := l.respond(ctx, msg.SessionID, text, usage)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "respond: session %s", msg.SessionID)
	}
	l.fireHook(l.hooks, hookRespond)

	// Step 6: AUDIT — log the interaction.
	l.audit(ctx, msg, out)
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
	// system prompt → active window history (which already includes the user message we just appended).
	messages := []provider.Message{
		{Role: store.MessageRoleSystem, Content: "You are a helpful assistant."},
	}
	for _, m := range history {
		messages = append(messages, provider.Message{
			Role:       m.Role,
			Content:    m.Content,
			ToolCallID: m.ToolCallID,
			ToolName:   m.ToolName,
		})
	}

	return session, messages, nil
}

func (l *Loop) callLLM(ctx context.Context, workspaceID string, session *store.Session, messages []provider.Message) (<-chan provider.ChatEvent, error) {
	modelName := session.ModelOverride
	if modelName == "" {
		modelName = "default"
	}

	prov, resolvedModel, err := l.providerRouter.Route(ctx, workspaceID, modelName)
	if err != nil {
		// Propagate budget errors directly so callers can handle them.
		if sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded) {
			return nil, err
		}
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "routing provider for workspace %s", workspaceID)
	}

	req := provider.ChatRequest{
		Model:    resolvedModel,
		Messages: messages,
		Options:  provider.ChatOptions{Stream: true},
	}

	eventCh, err := prov.Chat(ctx, req)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeProviderUpstreamFailure, "chat call to %s", prov.Name())
	}

	return eventCh, nil
}

func (l *Loop) processEvents(eventCh <-chan provider.ChatEvent) (string, []*provider.ToolCall, *provider.Usage, error) {
	var buf strings.Builder
	var toolCalls []*provider.ToolCall
	var usage *provider.Usage
	var streamErr error

	for ev := range eventCh {
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
	usage := initialUsage

	workspaceAllow := security.NewCapabilitySet("tool:*")
	userPerms := security.NewCapabilitySet("tool:*")

	for iteration := 0; iteration < maxToolLoopIterations; iteration++ {
		// If the LLM emitted text alongside tool calls, persist it as an
		// assistant message so the conversation history stays coherent.
		if text != "" {
			assistantMsg := &store.Message{
				ID:        uuid.New().String(),
				SessionID: msg.SessionID,
				Role:      store.MessageRoleAssistant,
				Content:   text,
				CreatedAt: time.Now(),
			}
			if err := l.sessions.AppendMessage(ctx, msg.SessionID, assistantMsg); err != nil {
				return "", nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "persisting assistant message: session %s", msg.SessionID)
			}
			currentMessages = append(currentMessages, provider.Message{
				Role:    store.MessageRoleAssistant,
				Content: text,
			})
		}

		// Dispatch each tool call and collect results.
		for _, tc := range currentToolCalls {
			req := ToolCallRequest{
				ToolName:        tc.Name,
				Arguments:       tc.Arguments,
				SessionID:       msg.SessionID,
				WorkspaceID:     msg.WorkspaceID,
				PluginName:      "builtin",
				TurnID:          turnID,
				WorkspaceAllow:  workspaceAllow,
				UserPermissions: userPerms,
			}

			result, err := l.toolDispatcher.ExecuteForTurn(ctx, req, l.maxToolCallsPerTurn)

			var resultContent string
			if err != nil {
				// On dispatch failure, send the error as the tool result
				// so the LLM can see it and decide how to proceed.
				resultContent = fmt.Sprintf("error: %s", err.Error())
			} else {
				resultContent = result.Content
			}

			// Persist tool result message.
			toolMsg := &store.Message{
				ID:         uuid.New().String(),
				SessionID:  msg.SessionID,
				Role:       store.MessageRoleTool,
				Content:    resultContent,
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
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
			})
		}

		// Re-call the LLM with updated message history.
		eventCh, err := l.callLLM(ctx, msg.WorkspaceID, session, currentMessages)
		if err != nil {
			return "", nil, err
		}

		text, currentToolCalls, usage, err = l.processEvents(eventCh)
		if err != nil {
			return "", nil, sigilerr.Wrapf(err, sigilerr.CodeProviderUpstreamFailure, "stream error in tool loop: session %s", msg.SessionID)
		}

		// If no more tool calls, the loop is done.
		if len(currentToolCalls) == 0 {
			break
		}
	}

	return text, usage, nil
}

func (l *Loop) respond(ctx context.Context, sessionID, text string, usage *provider.Usage) (*OutboundMessage, error) {
	// Persist the assistant response.
	assistantMsg := &store.Message{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		Role:      store.MessageRoleAssistant,
		Content:   text,
		CreatedAt: time.Now(),
	}
	if err := l.sessions.AppendMessage(ctx, sessionID, assistantMsg); err != nil {
		return nil, err
	}

	return &OutboundMessage{
		SessionID: sessionID,
		Content:   text,
		Usage:     usage,
	}, nil
}

func (l *Loop) audit(ctx context.Context, msg InboundMessage, out *OutboundMessage) {
	if l.auditStore == nil {
		return
	}

	entry := &store.AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Action:      "agent_loop.message",
		Actor:       msg.UserID,
		WorkspaceID: msg.WorkspaceID,
		SessionID:   msg.SessionID,
		Details:     map[string]any{"content_length": len(out.Content)},
		Result:      "ok",
	}

	// Best-effort audit; do not fail the response on audit errors.
	_ = l.auditStore.Append(ctx, entry)
}

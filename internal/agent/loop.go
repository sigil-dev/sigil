// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

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
	SessionManager *SessionManager
	Enforcer       *security.Enforcer
	ProviderRouter provider.Router
	AuditStore     store.AuditStore
	Hooks          *LoopHooks
}

// Loop is the agent's core processing pipeline.
type Loop struct {
	sessions       *SessionManager
	enforcer       *security.Enforcer
	providerRouter provider.Router
	auditStore     store.AuditStore
	hooks          *LoopHooks
}

// NewLoop creates a Loop with the given dependencies.
func NewLoop(cfg LoopConfig) *Loop {
	return &Loop{
		sessions:       cfg.SessionManager,
		enforcer:       cfg.Enforcer,
		providerRouter: cfg.ProviderRouter,
		auditStore:     cfg.AuditStore,
		hooks:          cfg.Hooks,
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
	text, usage := l.processEvents(eventCh)
	l.fireHook(l.hooks, hookProcess)

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

func (l *Loop) prepare(ctx context.Context, msg InboundMessage) (*store.Session, []provider.Message, error) {
	session, err := l.sessions.Get(ctx, msg.SessionID)
	if err != nil {
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
	// system prompt → active window history → new user message.
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
	messages = append(messages, provider.Message{
		Role:    store.MessageRoleUser,
		Content: msg.Content,
	})

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

func (l *Loop) processEvents(eventCh <-chan provider.ChatEvent) (string, *provider.Usage) {
	var buf strings.Builder
	var usage *provider.Usage

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
			// Tool dispatch is Task 4 — collect but don't process.
		case provider.EventTypeError:
			// Errors in the stream are noted but not fatal for now.
		}
	}

	return buf.String(), usage
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

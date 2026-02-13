// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// RegisterServices sets the service dependencies and registers REST routes.
func (s *Server) RegisterServices(svc *Services) {
	s.services = svc
	s.registerRoutes()
}

func (s *Server) registerRoutes() {
	// Workspace endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-workspaces",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces",
		Summary:     "List workspaces",
		Tags:        []string{"workspaces"},
	}, s.handleListWorkspaces)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-workspace",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}",
		Summary:     "Get workspace details",
		Tags:        []string{"workspaces"},
	}, s.handleGetWorkspace)

	// Session endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-sessions",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}/sessions",
		Summary:     "List sessions in workspace",
		Tags:        []string{"sessions"},
	}, s.handleListSessions)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-session",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}/sessions/{sessionId}",
		Summary:     "Get session details",
		Tags:        []string{"sessions"},
	}, s.handleGetSession)

	// Plugin endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-plugins",
		Method:      http.MethodGet,
		Path:        "/api/v1/plugins",
		Summary:     "List installed plugins",
		Tags:        []string{"plugins"},
	}, s.handleListPlugins)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-plugin",
		Method:      http.MethodGet,
		Path:        "/api/v1/plugins/{name}",
		Summary:     "Get plugin details",
		Tags:        []string{"plugins"},
	}, s.handleGetPlugin)

	huma.Register(s.api, huma.Operation{
		OperationID: "reload-plugin",
		Method:      http.MethodPost,
		Path:        "/api/v1/plugins/{name}/reload",
		Summary:     "Reload a plugin",
		Tags:        []string{"plugins"},
	}, s.handleReloadPlugin)

	// Chat endpoint (non-streaming, delegates to stream handler)
	huma.Register(s.api, huma.Operation{
		OperationID: "send-message",
		Method:      http.MethodPost,
		Path:        "/api/v1/chat",
		Summary:     "Send a message to the agent",
		Tags:        []string{"chat"},
	}, s.handleSendMessage)

	// User endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-users",
		Method:      http.MethodGet,
		Path:        "/api/v1/users",
		Summary:     "List users",
		Tags:        []string{"users"},
	}, s.handleListUsers)

	// Status endpoint
	huma.Register(s.api, huma.Operation{
		OperationID: "gateway-status",
		Method:      http.MethodGet,
		Path:        "/api/v1/status",
		Summary:     "Gateway status",
		Tags:        []string{"system"},
	}, s.handleStatus)
}

// --- Request/Response types for huma ---

type listWorkspacesOutput struct {
	Body struct {
		Workspaces []WorkspaceSummary `json:"workspaces"`
	}
}

type getWorkspaceInput struct {
	ID string `path:"id"`
}
type getWorkspaceOutput struct {
	Body WorkspaceDetail
}

type listSessionsInput struct {
	ID string `path:"id"`
}
type listSessionsOutput struct {
	Body struct {
		Sessions []SessionSummary `json:"sessions"`
	}
}

type getSessionInput struct {
	ID        string `path:"id"`
	SessionID string `path:"sessionId"`
}
type getSessionOutput struct {
	Body SessionDetail
}

type listPluginsOutput struct {
	Body struct {
		Plugins []PluginSummary `json:"plugins"`
	}
}

type pluginNameInput struct {
	Name string `path:"name"`
}
type getPluginOutput struct {
	Body PluginDetail
}

type reloadPluginOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

type sendMessageInput struct {
	Body struct {
		Content     string `json:"content" minLength:"1" doc:"Message content"`
		WorkspaceID string `json:"workspace_id" doc:"Target workspace"`
		SessionID   string `json:"session_id,omitempty" doc:"Optional session ID"`
	}
}
type sendMessageOutput struct {
	Body struct {
		Content   string `json:"content" doc:"Agent response"`
		SessionID string `json:"session_id" doc:"Session used"`
	}
}

type listUsersOutput struct {
	Body struct {
		Users []UserSummary `json:"users"`
	}
}

type statusOutput struct {
	Body struct {
		Status string `json:"status" example:"ok" doc:"Gateway status"`
	}
}

// --- Handlers ---

func (s *Server) handleListWorkspaces(ctx context.Context, _ *struct{}) (*listWorkspacesOutput, error) {
	ws, err := s.services.Workspaces.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("listing workspaces", err)
	}
	out := &listWorkspacesOutput{}
	out.Body.Workspaces = ws
	return out, nil
}

func (s *Server) handleGetWorkspace(ctx context.Context, input *getWorkspaceInput) (*getWorkspaceOutput, error) {
	ws, err := s.services.Workspaces.Get(ctx, input.ID)
	if err != nil {
		return nil, huma.Error404NotFound(fmt.Sprintf("workspace %q not found", input.ID))
	}
	return &getWorkspaceOutput{Body: *ws}, nil
}

func (s *Server) handleListSessions(ctx context.Context, input *listSessionsInput) (*listSessionsOutput, error) {
	sessions, err := s.services.Sessions.List(ctx, input.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("listing sessions", err)
	}
	out := &listSessionsOutput{}
	out.Body.Sessions = sessions
	return out, nil
}

func (s *Server) handleGetSession(ctx context.Context, input *getSessionInput) (*getSessionOutput, error) {
	session, err := s.services.Sessions.Get(ctx, input.ID, input.SessionID)
	if err != nil {
		return nil, huma.Error404NotFound(fmt.Sprintf("session %q not found", input.SessionID))
	}
	return &getSessionOutput{Body: *session}, nil
}

func (s *Server) handleListPlugins(ctx context.Context, _ *struct{}) (*listPluginsOutput, error) {
	plugins, err := s.services.Plugins.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("listing plugins", err)
	}
	out := &listPluginsOutput{}
	out.Body.Plugins = plugins
	return out, nil
}

func (s *Server) handleGetPlugin(ctx context.Context, input *pluginNameInput) (*getPluginOutput, error) {
	p, err := s.services.Plugins.Get(ctx, input.Name)
	if err != nil {
		return nil, huma.Error404NotFound(fmt.Sprintf("plugin %q not found", input.Name))
	}
	return &getPluginOutput{Body: *p}, nil
}

func (s *Server) handleReloadPlugin(ctx context.Context, input *pluginNameInput) (*reloadPluginOutput, error) {
	if err := s.services.Plugins.Reload(ctx, input.Name); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, huma.Error404NotFound(fmt.Sprintf("plugin %q not found", input.Name))
		}
		return nil, huma.Error500InternalServerError(fmt.Sprintf("reloading plugin %q", input.Name), err)
	}
	out := &reloadPluginOutput{}
	out.Body.Status = "reloaded"
	return out, nil
}

func (s *Server) handleSendMessage(ctx context.Context, input *sendMessageInput) (*sendMessageOutput, error) {
	if s.streamHandler == nil {
		return nil, huma.Error503ServiceUnavailable("agent not configured")
	}

	// Derive a cancellable context so we can signal the stream handler to stop
	// on early return (e.g. error event), preventing goroutine leaks.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(ctx, ChatStreamRequest{
		Content:     input.Body.Content,
		WorkspaceID: input.Body.WorkspaceID,
		SessionID:   input.Body.SessionID,
	}, ch)

	var content string
	sessionID := input.Body.SessionID

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				// Channel closed — stream finished.
				out := &sendMessageOutput{}
				out.Body.Content = content
				out.Body.SessionID = sessionID
				return out, nil
			}
			switch event.Event {
			case "text_delta":
				content += extractText(event.Data)
			case "session_id":
				sessionID = extractSessionID(event.Data, sessionID)
			case "error":
				msg := extractErrorMessage(event.Data)
				// Cancel context and drain remaining events to unblock the
				// stream handler goroutine before returning.
				cancel()
				go func() {
					for range ch {
					}
				}()
				return nil, huma.Error502BadGateway(msg)
			}
		case <-ctx.Done():
			return nil, huma.Error504GatewayTimeout("request timed out")
		}
	}
}

// extractSessionID parses a session_id event payload and returns the session ID.
// Falls back to the provided fallback if parsing fails.
func extractSessionID(data string, fallback string) string {
	var payload struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil || payload.SessionID == "" {
		return fallback
	}
	return payload.SessionID
}

// extractErrorMessage parses an error event payload and returns a human-readable message.
func extractErrorMessage(data string) string {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return data
	}
	if payload.Message != "" {
		return payload.Message
	}
	if payload.Error != "" {
		return payload.Error
	}
	return "unknown stream error"
}

// extractText parses a JSON text_delta payload and returns the text field.
// Falls back to the raw string if parsing fails.
func extractText(data string) string {
	var delta struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(data), &delta); err != nil {
		return data
	}
	return delta.Text
}

func (s *Server) handleListUsers(ctx context.Context, _ *struct{}) (*listUsersOutput, error) {
	users, err := s.services.Users.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("listing users", err)
	}
	out := &listUsersOutput{}
	out.Body.Users = users
	return out, nil
}

func (s *Server) handleStatus(_ context.Context, _ *struct{}) (*statusOutput, error) {
	out := &statusOutput{}
	out.Body.Status = "ok"
	return out, nil
}

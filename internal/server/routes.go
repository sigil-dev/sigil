// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

func (s *Server) registerRoutes() {
	// Workspace endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-workspaces",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces",
		Summary:     "List workspaces",
		Tags:        []string{"workspaces"},
		Errors:      []int{http.StatusTooManyRequests},
	}, s.handleListWorkspaces)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-workspace",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}",
		Summary:     "Get workspace details",
		Tags:        []string{"workspaces"},
		Errors:      []int{http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleGetWorkspace)

	// Session endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-sessions",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}/sessions",
		Summary:     "List sessions in workspace",
		Tags:        []string{"sessions"},
		Errors:      []int{http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleListSessions)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-session",
		Method:      http.MethodGet,
		Path:        "/api/v1/workspaces/{id}/sessions/{sessionId}",
		Summary:     "Get session details",
		Tags:        []string{"sessions"},
		Errors:      []int{http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleGetSession)

	// Plugin endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-plugins",
		Method:      http.MethodGet,
		Path:        "/api/v1/plugins",
		Summary:     "List installed plugins",
		Tags:        []string{"plugins"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleListPlugins)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-plugin",
		Method:      http.MethodGet,
		Path:        "/api/v1/plugins/{name}",
		Summary:     "Get plugin details",
		Tags:        []string{"plugins"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleGetPlugin)

	huma.Register(s.api, huma.Operation{
		OperationID: "reload-plugin",
		Method:      http.MethodPost,
		Path:        "/api/v1/plugins/{name}/reload",
		Summary:     "Reload a plugin",
		Tags:        []string{"plugins"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleReloadPlugin)

	// Provider health endpoint (only when ProviderService is available)
	if s.services.Providers() != nil {
		huma.Register(s.api, huma.Operation{
			OperationID: "get-provider-health",
			Method:      http.MethodGet,
			Path:        "/api/v1/providers/{name}/health",
			Summary:     "Get provider health metrics",
			Tags:        []string{"providers"},
			Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests},
		}, s.handleGetProviderHealth)
	}

	// Chat endpoint (non-streaming, delegates to stream handler)
	huma.Register(s.api, huma.Operation{
		OperationID: "send-message",
		Method:      http.MethodPost,
		Path:        "/api/v1/chat",
		Summary:     "Send a message to the agent",
		Tags:        []string{"chat"},
		Errors:      []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable},
	}, s.handleSendMessage)

	// User endpoints
	huma.Register(s.api, huma.Operation{
		OperationID: "list-users",
		Method:      http.MethodGet,
		Path:        "/api/v1/users",
		Summary:     "List users",
		Tags:        []string{"users"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests},
	}, s.handleListUsers)

	// Status endpoint
	huma.Register(s.api, huma.Operation{
		OperationID: "gateway-status",
		Method:      http.MethodGet,
		Path:        "/api/v1/status",
		Summary:     "Gateway status",
		Tags:        []string{"system"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests},
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

type providerNameInput struct {
	Name string `path:"name"`
}
type getProviderHealthOutput struct {
	Body ProviderHealthDetail
}

// --- Handlers ---

// notFoundOr500 maps a service error to a 404 (if the error carries the
// not-found code) or a generic 500. The full error is logged server-side
// so that 5xx responses never leak internal details.
func notFoundOr500(err error, notFoundMsg, context string) error {
	if IsNotFound(err) {
		return huma.Error404NotFound(notFoundMsg)
	}
	slog.Error("internal error", "context", context, "error", err)
	return huma.Error500InternalServerError("internal server error")
}

func (s *Server) handleListWorkspaces(ctx context.Context, _ *struct{}) (*listWorkspacesOutput, error) {
	// When auth is enabled, use ListForUser for membership-filtered results.
	user := UserFromContext(ctx)
	var ws []WorkspaceSummary
	var err error
	if user != nil {
		ws, err = s.services.Workspaces().ListForUser(ctx, user.ID())
	} else {
		ws, err = s.services.Workspaces().List(ctx)
	}
	if err != nil {
		slog.Error("internal error", "context", "listing workspaces", "error", err)
		return nil, huma.Error500InternalServerError("internal server error")
	}

	out := &listWorkspacesOutput{}
	out.Body.Workspaces = ws
	return out, nil
}

func (s *Server) handleGetWorkspace(ctx context.Context, input *getWorkspaceInput) (*getWorkspaceOutput, error) {
	if err := s.checkWorkspaceMembership(ctx, input.ID); err != nil {
		return nil, err
	}

	ws, err := s.services.Workspaces().Get(ctx, input.ID)
	if err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("workspace %q not found", input.ID),
			fmt.Sprintf("getting workspace %q", input.ID))
	}
	return &getWorkspaceOutput{Body: *ws}, nil
}

func (s *Server) handleListSessions(ctx context.Context, input *listSessionsInput) (*listSessionsOutput, error) {
	if err := s.checkWorkspaceMembership(ctx, input.ID); err != nil {
		return nil, err
	}

	sessions, err := s.services.Sessions().List(ctx, input.ID)
	if err != nil {
		slog.Error("internal error", "context", "listing sessions", "error", err)
		return nil, huma.Error500InternalServerError("internal server error")
	}
	out := &listSessionsOutput{}
	out.Body.Sessions = sessions
	return out, nil
}

func (s *Server) handleGetSession(ctx context.Context, input *getSessionInput) (*getSessionOutput, error) {
	if err := s.checkWorkspaceMembership(ctx, input.ID); err != nil {
		return nil, err
	}

	session, err := s.services.Sessions().Get(ctx, input.ID, input.SessionID)
	if err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("session %q not found", input.SessionID),
			fmt.Sprintf("getting session %q", input.SessionID))
	}
	return &getSessionOutput{Body: *session}, nil
}

// requireAdmin checks that the caller has the given admin permission.
// When auth is disabled (dev mode), the operation is allowed with an info log.
// When auth is enabled but no user is present, 401 is returned (defense-in-depth).
// When the user lacks the required permission, 403 is returned.
func (s *Server) requireAdmin(ctx context.Context, permission, op string) error {
	user := UserFromContext(ctx)
	if user == nil {
		if s.authDisabled() {
			slog.Info("admin operation without authentication (auth disabled)", "op", op)
			return nil
		}
		return huma.Error401Unauthorized("authentication required")
	}
	if !user.HasPermission(permission) {
		return huma.Error403Forbidden(fmt.Sprintf("insufficient permissions to %s", op))
	}
	return nil
}

func (s *Server) handleListPlugins(ctx context.Context, _ *struct{}) (*listPluginsOutput, error) {
	if err := s.requireAdmin(ctx, "admin:plugins", "list plugins"); err != nil {
		return nil, err
	}

	plugins, err := s.services.Plugins().List(ctx)
	if err != nil {
		slog.Error("internal error", "context", "listing plugins", "error", err)
		return nil, huma.Error500InternalServerError("internal server error")
	}
	out := &listPluginsOutput{}
	out.Body.Plugins = plugins
	return out, nil
}

func (s *Server) handleGetPlugin(ctx context.Context, input *pluginNameInput) (*getPluginOutput, error) {
	if err := s.requireAdmin(ctx, "admin:plugins", "get plugin details"); err != nil {
		return nil, err
	}

	p, err := s.services.Plugins().Get(ctx, input.Name)
	if err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("plugin %q not found", input.Name),
			fmt.Sprintf("getting plugin %q", input.Name))
	}
	return &getPluginOutput{Body: *p}, nil
}

func (s *Server) handleReloadPlugin(ctx context.Context, input *pluginNameInput) (*reloadPluginOutput, error) {
	if err := s.requireAdmin(ctx, "admin:plugins", "reload plugins"); err != nil {
		return nil, err
	}

	if err := s.services.Plugins().Reload(ctx, input.Name); err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("plugin %q not found", input.Name),
			fmt.Sprintf("reloading plugin %q", input.Name))
	}
	out := &reloadPluginOutput{}
	out.Body.Status = "reloaded"
	return out, nil
}

func (s *Server) handleSendMessage(ctx context.Context, input *sendMessageInput) (*sendMessageOutput, error) {
	if s.streamHandler == nil {
		err503 := huma.Error503ServiceUnavailable("agent not configured")
		return nil, huma.ErrorWithHeaders(err503, http.Header{"Retry-After": []string{"5"}})
	}
	if err := s.checkChatRequestLimit(ctx, "/api/v1/chat"); err != nil {
		return nil, err
	}

	// Verify workspace membership.
	if err := s.checkWorkspaceMembership(ctx, input.Body.WorkspaceID); err != nil {
		return nil, err
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
				code, msg := extractErrorEvent(event.Data)
				// Cancel context and drain remaining events to unblock the
				// stream handler goroutine before returning.
				cancel()
				drainSSEChannel(ch)
				return nil, errorCodeToHTTPError(code, msg)
			default:
				truncated := truncateForLogging(event.Data, 100)
				slog.Warn("handleSendMessage: unknown SSE event type, skipping",
					"event_type", event.Event,
					"expected_types", []string{"text_delta", "session_id", "error"},
					"event_data", truncated,
				)
			}
		case <-ctx.Done():
			return nil, huma.Error504GatewayTimeout("request timed out")
		}
	}
}

const (
	// maxTextContentBytes is the maximum size for text content returned to clients
	// when JSON parsing fails. This prevents malicious streams from leaking
	// megabytes of data to the client.
	maxTextContentBytes = 10240 // 10KB
)

// truncateForLogging returns s truncated to maxLen with "..." suffix if needed.
func truncateForLogging(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// extractSessionID parses a session_id event payload and returns the session ID.
// Falls back to the provided fallback if parsing fails.
func extractSessionID(data string, fallback string) string {
	var payload struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		truncated := truncateForLogging(data, 100)
		slog.Warn("failed to parse session_id event, using fallback",
			"raw_data", truncated,
			"error", err,
			"fallback", fallback,
		)
		return fallback
	}
	if payload.SessionID == "" {
		slog.Warn("session_id event has empty session_id field, using fallback",
			"raw_data", data,
			"fallback", fallback,
		)
		return fallback
	}
	return payload.SessionID
}

// extractErrorEvent parses an error event payload and returns the error code and a
// human-readable message. The returned message is bounded to 200 characters to
// prevent unbounded data leaks from malicious/buggy stream handlers.
func extractErrorEvent(data string) (code string, message string) {
	var payload struct {
		Code    string `json:"code"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		truncated := truncateForLogging(data, 100)
		slog.Warn("failed to parse SSE error event payload, returning generic message",
			"raw_data", truncated,
			"error", err,
		)
		return "", "agent reported an error; details unavailable"
	}
	if payload.Message != "" {
		return payload.Code, truncateForLogging(payload.Message, 200)
	}
	if payload.Error != "" {
		return payload.Code, truncateForLogging(payload.Error, 200)
	}
	return payload.Code, "unknown stream error"
}

// errorCodeToHTTPError maps a sigilerr error code string (received via SSE) to the
// appropriate huma HTTP error. Delegates to sigilerr.HTTPStatusFromCode for canonical
// status mapping so that classification logic is not duplicated here.
func errorCodeToHTTPError(code, message string) error {
	if code == "" {
		slog.Warn("errorCodeToHTTPError: empty error code from SSE event, defaulting to 502",
			"message", message,
		)
	}
	status := sigilerr.HTTPStatusFromCode(sigilerr.Code(code))
	return huma.NewError(status, message)
}

// extractText parses a JSON text_delta payload and returns the text field.
// Falls back to the raw string if parsing fails (truncated to maxTextContentBytes).
func extractText(data string) string {
	var delta struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(data), &delta); err != nil {
		truncated := truncateForLogging(data, 100)
		slog.Warn("failed to parse text_delta event, using raw string as fallback",
			"raw_data", truncated,
			"error", err,
		)
		// Truncate fallback to prevent data leak from malicious streams
		return truncateForLogging(data, maxTextContentBytes)
	}
	return delta.Text
}

func (s *Server) handleListUsers(ctx context.Context, _ *struct{}) (*listUsersOutput, error) {
	if err := s.requireAdmin(ctx, "admin:users", "list users"); err != nil {
		return nil, err
	}

	users, err := s.services.Users().List(ctx)
	if err != nil {
		slog.Error("internal error", "context", "listing users", "error", err)
		return nil, huma.Error500InternalServerError("internal server error")
	}
	out := &listUsersOutput{}
	out.Body.Users = users
	return out, nil
}

func (s *Server) handleGetProviderHealth(ctx context.Context, input *providerNameInput) (*getProviderHealthOutput, error) {
	if err := s.requireAdmin(ctx, "admin:providers", "get provider health"); err != nil {
		return nil, err
	}

	detail, err := s.services.Providers().GetHealth(ctx, input.Name)
	if err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("provider %q not found", input.Name),
			fmt.Sprintf("getting provider health %q", input.Name))
	}
	if detail == nil {
		internalErr := sigilerr.New(sigilerr.CodeServerInternalFailure, "GetHealth contract violation: nil detail with nil error")
		return nil, notFoundOr500(internalErr, "", fmt.Sprintf("getting provider health %q", input.Name))
	}
	return &getProviderHealthOutput{Body: *detail}, nil
}

func (s *Server) handleStatus(ctx context.Context, _ *struct{}) (*statusOutput, error) {
	if err := s.requireAdmin(ctx, "admin:status", "get gateway status"); err != nil {
		return nil, err
	}

	out := &statusOutput{}
	out.Body.Status = "ok"
	return out, nil
}

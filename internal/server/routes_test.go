// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock service implementations for testing.
type mockWorkspaceService struct{}

func (m *mockWorkspaceService) List(_ context.Context) ([]server.WorkspaceSummary, error) {
	return []server.WorkspaceSummary{
		{ID: "homelab", Description: "Home automation"},
		{ID: "dev", Description: "Development"},
	}, nil
}

func (m *mockWorkspaceService) Get(_ context.Context, id string) (*server.WorkspaceDetail, error) {
	if id == "homelab" {
		return &server.WorkspaceDetail{
			ID:          "homelab",
			Description: "Home automation",
			Members:     []string{"user-1"},
		}, nil
	}
	return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "workspace %q not found", id)
}

type mockPluginService struct{}

func (m *mockPluginService) List(_ context.Context) ([]server.PluginSummary, error) {
	return []server.PluginSummary{
		{Name: "anthropic", Type: "provider", Version: "1.0.0", Status: "running"},
	}, nil
}

func (m *mockPluginService) Get(_ context.Context, name string) (*server.PluginDetail, error) {
	if name == "anthropic" {
		return &server.PluginDetail{
			Name: "anthropic", Type: "provider", Version: "1.0.0",
			Status: "running", Tier: "process", Capabilities: []string{"provider.chat"},
		}, nil
	}
	return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "plugin %q not found", name)
}

func (m *mockPluginService) Reload(_ context.Context, name string) error {
	if name == "anthropic" {
		return nil
	}
	return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "plugin %q not found", name)
}

// errorPluginService returns a non-"not found" error from Reload to test 5xx mapping.
type errorPluginService struct{ mockPluginService }

func (m *errorPluginService) Reload(_ context.Context, _ string) error {
	return fmt.Errorf("connection refused")
}

type mockSessionService struct{}

func (m *mockSessionService) List(_ context.Context, _ string) ([]server.SessionSummary, error) {
	return []server.SessionSummary{
		{ID: "sess-1", WorkspaceID: "homelab", Status: "active"},
	}, nil
}

func (m *mockSessionService) Get(_ context.Context, _, sessionID string) (*server.SessionDetail, error) {
	if sessionID == "sess-1" {
		return &server.SessionDetail{
			ID: "sess-1", WorkspaceID: "homelab", Status: "active", MessageCount: 5,
		}, nil
	}
	return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "session %q not found", sessionID)
}

type mockUserService struct{}

func (m *mockUserService) List(_ context.Context) ([]server.UserSummary, error) {
	return []server.UserSummary{
		{ID: "user-1", Name: "Sean"},
	}, nil
}

func newTestServerWithData(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)

	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	return srv
}

// newTestServerWithStream creates a test server with standard mock services and the given stream handler.
func newTestServerWithStream(t *testing.T, handler server.StreamHandler) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	if handler != nil {
		srv.RegisterStreamHandler(handler)
	}
	return srv
}

func TestRoutes_ListWorkspaces(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Body struct {
			Workspaces []server.WorkspaceSummary `json:"workspaces"`
		}
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp.Body)
	require.NoError(t, err)
	assert.Len(t, resp.Body.Workspaces, 2)
}

func TestRoutes_GetWorkspace(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "homelab")
}

func TestRoutes_GetWorkspace_NotFound(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoutes_ListSessions(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_GetSession(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab/sessions/sess-1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sess-1")
}

func TestRoutes_ListPlugins(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "anthropic")
}

func TestRoutes_GetPlugin(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/anthropic", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "anthropic")
}

func TestRoutes_ReloadPlugin(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_ReloadPlugin_NotFound(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/nonexistent/reload", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoutes_ReloadPlugin_InternalError(t *testing.T) {
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &errorPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/failing/reload", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Non-"not found" errors must produce 500, not 404.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRoutes_SendMessage(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "text_delta", Data: `{"text":" world"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello, agent!", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Hello world", resp.Content)
}

func TestRoutes_SendMessage_SessionFromStream(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "session_id", Data: `{"session_id":"sess-new-123"}`},
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "text_delta", Data: `{"text":" there"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	// Request with NO session_id — backend creates one.
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Hello there", resp.Content)
	assert.Equal(t, "sess-new-123", resp.SessionID, "should return session ID from stream, not request")
}

func TestRoutes_SendMessage_ErrorEvent(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"partial"}`},
		{Event: "error", Data: `{"error":"provider_error","message":"rate limit exceeded"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should NOT return 200 with partial content — must surface the error.
	assert.GreaterOrEqual(t, w.Code, 500, "error event must produce a server error status")
	assert.Contains(t, w.Body.String(), "rate limit exceeded")
}

// hangingStreamHandler blocks until release is closed, simulating a handler
// that never finishes.
type hangingStreamHandler struct {
	release chan struct{}
	mu      sync.Mutex
	started bool
}

func (h *hangingStreamHandler) HandleStream(_ context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	h.mu.Lock()
	h.started = true
	h.mu.Unlock()
	<-h.release
	close(ch)
}

func TestRoutes_SendMessage_ContextCancelled(t *testing.T) {
	handler := &hangingStreamHandler{release: make(chan struct{})}
	defer close(handler.release) // unblock goroutine on test cleanup

	srv := newTestServerWithStream(t, handler)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Attach a context that cancels after 100ms.
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	select {
	case <-done:
		// Handler returned — good.
	case <-time.After(5 * time.Second):
		t.Fatal("handleSendMessage hung instead of respecting context cancellation")
	}

	// Should return a timeout/error status, not 200.
	assert.GreaterOrEqual(t, w.Code, 400, "cancelled context must produce an error status")
}

func TestRoutes_SendMessage_InvalidJSON(t *testing.T) {
	srv := newTestServerWithData(t)
	srv.RegisterStreamHandler(&mockStreamHandler{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoutes_SendMessage_MissingContent(t *testing.T) {
	srv := newTestServerWithData(t)
	srv.RegisterStreamHandler(&mockStreamHandler{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(`{"workspace_id":"homelab"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestRoutes_ListUsers(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Sean")
}

func TestRoutes_Status(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestRoutes_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoutes_ReloadPlugin_AuthDisabled_Succeeds(t *testing.T) {
	// When auth is disabled (no validator), reload should succeed.
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "reloaded")
}

func TestRoutes_ReloadPlugin_InsufficientPermissions_Returns403(t *testing.T) {
	// User with no admin permissions should get 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Regular User",
				Permissions: []string{"workspace:read"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestRoutes_ReloadPlugin_WithAdminWildcard_Succeeds(t *testing.T) {
	// User with admin:* permission should succeed.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": {
				ID:          "admin-1",
				Name:        "Admin User",
				Permissions: []string{"admin:*"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "reloaded")
}

func TestRoutes_ReloadPlugin_WithExactPermission_Succeeds(t *testing.T) {
	// User with exact admin:reload permission should succeed.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": {
				ID:          "admin-1",
				Name:        "Admin User",
				Permissions: []string{"admin:reload"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "reloaded")
}

func TestRoutes_SendMessage_MalformedTextDelta(t *testing.T) {
	// This test verifies that malformed JSON in text_delta events is logged,
	// and the raw string is returned (fallback behavior).
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `not valid json`},
		{Event: "text_delta", Data: `{"text":"valid"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Fallback: raw string returned when JSON parsing fails.
	assert.Equal(t, "not valid jsonvalid", resp.Content)
}

func TestRoutes_SendMessage_MalformedSessionID(t *testing.T) {
	// This test verifies that malformed JSON in session_id events is logged,
	// and the fallback session ID is returned.
	events := []server.SSEEvent{
		{Event: "session_id", Data: `invalid json`},
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab", "session_id": "sess-fallback"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Fallback: original session ID returned when JSON parsing fails.
	assert.Equal(t, "sess-fallback", resp.SessionID)
}

func TestRoutes_SendMessage_WorkspaceMembership_AuthDisabled_AllowsAnyWorkspace(t *testing.T) {
	// When auth is disabled, all workspaces are accessible.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "any-workspace-id"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_SendMessage_WorkspaceMembership_ValidMember_Succeeds(t *testing.T) {
	// User who is a member of the workspace can send messages.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: events})

	// workspace "homelab" has member "user-1"
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_SendMessage_WorkspaceMembership_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-2",
				Name:        "Non-Member User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	// workspace "homelab" has member "user-1", not "user-2"
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "not a member of workspace")
}

func TestRoutes_SendMessage_WorkspaceMembership_WorkspaceNotFound_Returns404(t *testing.T) {
	// Non-existent workspace returns 404.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	body := `{"content": "Hello", "workspace_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "not found")
}

func TestRoutes_SendMessage_WorkspaceMembership_EmptyWorkspaceID_Succeeds(t *testing.T) {
	// When auth is enabled, empty workspace_id returns 422.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	body := `{"content": "Hello", "workspace_id": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "workspace_id is required")
}

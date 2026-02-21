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

	"github.com/danielgtaylor/huma/v2"
	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/plugin"
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

func (m *mockWorkspaceService) ListForUser(ctx context.Context, userID string) ([]server.WorkspaceSummary, error) {
	all, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []server.WorkspaceSummary
	for _, ws := range all {
		detail, err := m.Get(ctx, ws.ID)
		if err != nil {
			continue
		}
		for _, member := range detail.Members {
			if member == userID {
				out = append(out, ws)
				break
			}
		}
	}
	return out, nil
}

func (m *mockWorkspaceService) Get(_ context.Context, id string) (*server.WorkspaceDetail, error) {
	switch id {
	case "homelab":
		return &server.WorkspaceDetail{
			ID:          "homelab",
			Description: "Home automation",
			Members:     []string{"user-1"},
		}, nil
	case "dev":
		return &server.WorkspaceDetail{
			ID:          "dev",
			Description: "Development",
			Members:     []string{"user-3"},
		}, nil
	default:
		return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "workspace %q not found", id)
	}
}

type mockPluginService struct{}

func (m *mockPluginService) List(_ context.Context) ([]server.PluginSummary, error) {
	return []server.PluginSummary{
		{Name: "anthropic", Type: plugin.PluginTypeProvider, Version: "1.0.0", Status: server.PluginStatusRunning, Tier: plugin.ExecutionTierProcess},
	}, nil
}

func (m *mockPluginService) Get(_ context.Context, name string) (*server.PluginDetail, error) {
	if name == "anthropic" {
		return &server.PluginDetail{
			Name: "anthropic", Type: plugin.PluginTypeProvider, Version: "1.0.0",
			Status: server.PluginStatusRunning, Tier: plugin.ExecutionTierProcess, Capabilities: []string{"provider.chat"},
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
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// newTestServerWithStream creates a test server with standard mock services and the given stream handler.
func newTestServerWithStream(t *testing.T, handler server.StreamHandler) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: handler,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
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
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0", Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&errorPluginService{},
			&mockSessionService{},
			&mockUserService{}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

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
	srv := newTestServerWithStream(t, &mockStreamHandler{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoutes_SendMessage_MissingContent(t *testing.T) {
	srv := newTestServerWithStream(t, &mockStreamHandler{})

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

func TestRoutes_Status_AuthDisabled_Succeeds(t *testing.T) {
	// When auth is disabled, status endpoint should be accessible without auth.
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestRoutes_Status_AuthEnabled_WithoutToken_Returns401(t *testing.T) {
	// When auth is enabled and no token is provided, status endpoint should return 401.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:status"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	assert.Contains(t, resp["error"], "authorization header required")
}

func TestRoutes_Status_AuthEnabled_WithInvalidToken_Returns401(t *testing.T) {
	// When auth is enabled with invalid token, status endpoint should return 401.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:status"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRoutes_Status_AuthEnabled_WithoutAdminPermission_Returns403(t *testing.T) {
	// When auth is enabled but user lacks admin:status permission, return 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "User", []string{"workspace:read"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRoutes_Status_AuthEnabled_WithAdminToken_Returns200(t *testing.T) {
	// When auth is enabled and valid admin token is provided, status endpoint succeeds.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:status"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestRoutes_Status_AuthEnabled_WithWildcardAdminToken_Returns200(t *testing.T) {
	// When auth is enabled with wildcard admin:* permission, status endpoint succeeds.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:*"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
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
			"user-token": mustNewAuthenticatedUser("user-1", "Regular User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

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
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin User", []string{"admin:*"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "reloaded")
}

func TestRoutes_ReloadPlugin_WithExactPermission_Succeeds(t *testing.T) {
	// User with exact admin:plugins permission should succeed.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin User", []string{"admin:plugins"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/anthropic/reload", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "reloaded")
}

func TestRoutes_ListUsers_InsufficientPermissions_Returns403(t *testing.T) {
	// User without admin:users permission should get 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Regular User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestRoutes_ListPlugins_InsufficientPermissions_Returns403(t *testing.T) {
	// User without admin:plugins permission should get 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Regular User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestRoutes_GetPlugin_InsufficientPermissions_Returns403(t *testing.T) {
	// User without admin:plugins permission should get 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Regular User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/anthropic", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestRoutes_GetWorkspace_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member of the workspace gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-2", "Non-Member User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// workspace "homelab" has member "user-1", not "user-2"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestRoutes_ListSessions_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member of the workspace gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-2", "Non-Member User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// workspace "homelab" has member "user-1", not "user-2"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab/sessions", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestRoutes_GetSession_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member of the workspace gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-2", "Non-Member User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// workspace "homelab" has member "user-1", not "user-2"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/homelab/sessions/sess-1", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestRoutes_ListWorkspaces_FiltersByMembership(t *testing.T) {
	// When auth is enabled, only workspaces the user is a member of are returned.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Member User", []string{"workspace:read"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Workspaces []server.WorkspaceSummary `json:"workspaces"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// user-1 is only a member of "homelab" (see mockWorkspaceService.Get),
	// "dev" workspace returns not-found from Get so it's filtered out.
	assert.Len(t, resp.Workspaces, 1)
	assert.Equal(t, "homelab", resp.Workspaces[0].ID)
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

func TestRoutes_SendMessage_EmptySessionID(t *testing.T) {
	// This test verifies that a valid JSON session_id event with an empty string
	// value is ignored, and the fallback session ID from the request is returned.
	events := []server.SSEEvent{
		{Event: "session_id", Data: `{"session_id":""}`},
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
	// Fallback: original session ID returned when session_id event value is empty.
	assert.Equal(t, "sess-fallback", resp.SessionID)
}

func TestRoutes_SendMessage_WorkspaceMembership_AuthDisabled_AllowsAnyWorkspace(t *testing.T) {
	// When auth is disabled, all workspaces are accessible.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: events},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

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
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: events},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

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
			"user-token": mustNewAuthenticatedUser("user-2", "Non-Member User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// workspace "homelab" has member "user-1", not "user-2"
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestRoutes_SendMessage_WorkspaceMembership_WorkspaceNotFound_Returns403(t *testing.T) {
	// Non-existent workspace returns 403 to prevent enumeration.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	body := `{"content": "Hello", "workspace_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestRoutes_SendMessage_WorkspaceMembership_EmptyWorkspaceID_Succeeds(t *testing.T) {
	// When auth is enabled, empty workspace_id returns 422.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	body := `{"content": "Hello", "workspace_id": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "workspace_id is required")
}

func TestRoutes_RequireAdmin_AuthEnabled_NilUser_Returns401(t *testing.T) {
	// Defense-in-depth: when auth is enabled but user is nil in context,
	// requireAdmin must return 401 rather than falling through.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// Call requireAdmin with a bare context (no user).
	gotErr := srv.RequireAdmin(context.Background(), "admin:plugins", "test-op")
	require.Error(t, gotErr)
	se, ok := gotErr.(huma.StatusError)
	require.True(t, ok, "error should implement huma.StatusError")
	assert.Equal(t, 401, se.GetStatus())
}

func TestRoutes_RequireAdmin_AuthDisabled_NilUser_Allows(t *testing.T) {
	// When auth is disabled (no validator), admin operations are allowed.
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	gotErr := srv.RequireAdmin(context.Background(), "admin:plugins", "test-op")
	assert.NoError(t, gotErr)
}

func TestRoutes_RequireAdmin_UserWithPermission_Allows(t *testing.T) {
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	user := mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:plugins"})
	ctx := server.ContextWithUser(context.Background(), user)

	gotErr := srv.RequireAdmin(ctx, "admin:plugins", "test-op")
	assert.NoError(t, gotErr)
}

func TestRoutes_RequireAdmin_UserWithoutPermission_Returns403(t *testing.T) {
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	user := mustNewAuthenticatedUser("user-1", "Regular", []string{"workspace:read"})
	ctx := server.ContextWithUser(context.Background(), user)

	gotErr := srv.RequireAdmin(ctx, "admin:plugins", "test-op")
	require.Error(t, gotErr)
	se, ok := gotErr.(huma.StatusError)
	require.True(t, ok, "error should implement huma.StatusError")
	assert.Equal(t, 403, se.GetStatus())
	assert.Contains(t, gotErr.Error(), "insufficient permissions")
}

func TestRoutes_AdminEndpoints_AuthEnabled_NoToken_Returns401(t *testing.T) {
	// When auth is enabled and no token is provided, middleware returns 401
	// before the handler is reached.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:*"}),
		},
	}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/plugins"},
		{http.MethodGet, "/api/v1/plugins/anthropic"},
		{http.MethodPost, "/api/v1/plugins/anthropic/reload"},
		{http.MethodGet, "/api/v1/users"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			// No Authorization header — auth middleware should reject.
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestRoutes_SendMessage_ErrorEvent_Truncated(t *testing.T) {
	// This test verifies that unbounded error messages are truncated to 200 chars.
	// A malicious/buggy stream handler could produce multi-MB error responses.
	longMessage := strings.Repeat("x", 500) // 500 chars, exceeds 200-char limit
	events := []server.SSEEvent{
		{Event: "error", Data: `{"error":"provider_error","message":"` + longMessage + `"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should produce a 502 error due to the error event.
	assert.GreaterOrEqual(t, w.Code, 500, "error event must produce a server error status")

	// Response body should contain truncated error message (200 chars + "...")
	responseBody := w.Body.String()
	assert.True(t, len(responseBody) < 500, "response should not contain unbounded data (len=%d)", len(responseBody))

	// Verify the message is truncated with "..." suffix
	assert.Contains(t, responseBody, "...")
}

func TestRoutes_SendMessage_UnparsableErrorEvent_Truncated(t *testing.T) {
	// This test verifies that when JSON parsing fails in extractErrorEvent,
	// a safe generic message is returned instead of raw data.
	longInvalidData := strings.Repeat("y", 500) // 500 chars of invalid JSON
	events := []server.SSEEvent{
		{Event: "error", Data: longInvalidData},
		{Event: "done", Data: `{}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should produce a 502 error due to the error event.
	assert.GreaterOrEqual(t, w.Code, 500, "error event must produce a server error status")

	// Response body should contain the safe generic message, not raw data.
	assert.Contains(t, w.Body.String(), "agent reported an error; details unavailable")
}
// --- Part 1: Unknown event type warning ---

func TestRoutes_SendMessage_UnknownEventType_DoesNotPanic(t *testing.T) {
	// Unknown event types (tool_call, usage) must not panic and must be
	// silently skipped (with a slog.Warn) rather than causing incorrect behavior.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "tool_call", Data: `{"tool":"bash","args":{}}`},
		{Event: "usage", Data: `{"tokens":100}`},
		// Note: "done" is not a special sentinel — it would just be another
		// unknown event. Channel close ends the loop, not a "done" event.
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should succeed - unknown events are warnings, not errors.
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Only text_delta contributes to content.
	assert.Equal(t, "Hello", resp.Content)
}

// --- Part 2: Error code in SSE error event + HTTP status mapping ---

func TestRoutes_SendMessage_ErrorEvent_SecurityScannerInputBlocked_Returns422(t *testing.T) {
	// security.scanner.input_blocked is a client content rejection: 422 Unprocessable Entity.
	code := string(sigilerr.CodeSecurityScannerInputBlocked)
	events := []server.SSEEvent{
		{Event: "error", Data: `{"code":"` + code + `","message":"blocked by security policy","error":"` + code + `"}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code,
		"security.scanner.input_blocked must produce 422 Unprocessable Entity")
	assert.Contains(t, w.Body.String(), "blocked by security policy")
}

func TestRoutes_SendMessage_ErrorEvent_SecurityScannerOtherCodes_Returns503(t *testing.T) {
	// All security.scanner.* codes other than input_blocked are service-side transient: 503.
	tests := []struct {
		name string
		code sigilerr.Code
	}{
		{"tool_blocked", sigilerr.CodeSecurityScannerToolBlocked},
		{"output_blocked", sigilerr.CodeSecurityScannerOutputBlocked},
		{"content_too_large", sigilerr.CodeSecurityScannerContentTooLarge},
		{"failure", sigilerr.CodeSecurityScannerFailure},
		{"cancelled", sigilerr.CodeSecurityScannerCancelled},
		{"circuit_breaker_open", sigilerr.CodeSecurityScannerCircuitBreakerOpen},
		{"empty_rule_stage", sigilerr.CodeSecurityScannerEmptyRuleStage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := string(tt.code)
			events := []server.SSEEvent{
				{Event: "error", Data: `{"code":"` + code + `","message":"blocked by security policy","error":"` + code + `"}`},
			}
			srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

			body := `{"content": "Hello", "workspace_id": "homelab"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusServiceUnavailable, w.Code,
				"security scanner code %q must produce 503 Service Unavailable", code)
			assert.Contains(t, w.Body.String(), "blocked by security policy")
		})
	}
}

func TestRoutes_SendMessage_ErrorEvent_SecurityCapabilityAndInputCodes_Returns400(t *testing.T) {
	// security.capability.invalid and security.input.invalid must also map to 400.
	codes := []string{
		string(sigilerr.CodeSecurityCapabilityInvalid),
		string(sigilerr.CodeSecurityInvalidInput),
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			events := []server.SSEEvent{
				{Event: "error", Data: `{"code":"` + code + `","message":"invalid request","error":"` + code + `"}`},
			}
			srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

			body := `{"content": "Hello", "workspace_id": "homelab"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code,
				"security code %q must produce 400 Bad Request", code)
		})
	}
}

func TestRoutes_SendMessage_ErrorEvent_OtherErrorCodes_Returns502(t *testing.T) {
	// Non-security error codes must map to 502 Bad Gateway (infra/provider failure).
	tests := []struct {
		name string
		data string
	}{
		{
			name: "provider upstream failure",
			data: `{"code":"provider.upstream.failure","message":"rate limit exceeded","error":"provider.upstream.failure"}`,
		},
		{
			name: "no code field (backward compat)",
			data: `{"error":"provider_error","message":"rate limit exceeded"}`,
		},
		{
			name: "unknown code",
			data: `{"code":"some.unknown.code","message":"something failed","error":"some.unknown.code"}`,
		},
		{
			name: "empty code",
			data: `{"code":"","message":"empty code","error":"empty"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []server.SSEEvent{
				{Event: "error", Data: tt.data},
			}
			srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

			body := `{"content": "Hello", "workspace_id": "homelab"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadGateway, w.Code,
				"test %q: non-security error must produce 502 Bad Gateway", tt.name)
		})
	}
}

func TestRoutes_SendMessage_ErrorEvent_BudgetAndTimeoutCodes(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantStatus int
	}{
		{
			name:       "budget exceeded → 429",
			data:       `{"code":"agent.tool.budget_exceeded","message":"tool call budget exceeded"}`,
			wantStatus: http.StatusTooManyRequests,
		},
		{
			name:       "provider budget exceeded → 429",
			data:       `{"code":"provider.budget.exceeded","message":"provider budget exceeded"}`,
			wantStatus: http.StatusTooManyRequests,
		},
		{
			name:       "tool timeout → 504",
			data:       `{"code":"agent.tool.timeout","message":"tool execution timed out"}`,
			wantStatus: http.StatusGatewayTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []server.SSEEvent{
				{Event: "error", Data: tt.data},
			}
			srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

			body := `{"content": "Hello", "workspace_id": "homelab"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code,
				"test %q: expected HTTP %d", tt.name, tt.wantStatus)
		})
	}
}

func TestRoutes_SendMessage_ErrorEvent_CodeFieldParsed(t *testing.T) {
	// Verify the code field is parsed from the SSE error payload.
	// security.scanner.input_blocked → 422 Unprocessable Entity (client content rejection).
	events := []server.SSEEvent{
		{Event: "error", Data: `{"code":"security.scanner.input_blocked","message":"your input was blocked","error":"security.scanner.input_blocked"}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "your input was blocked")
}

func TestRoutes_SendMessage_ErrorEvent_MessageTakesPriorityOverError(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "error", Data: `{"code":"provider.upstream.failure","error":"err_short","message":"human readable message"}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "human readable message")
	assert.NotContains(t, w.Body.String(), "err_short")
}

func TestRoutes_SendMessage_ErrorEvent_CodeOnlyPayload_FallbackMessage(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "error", Data: `{"code":"security.scanner.input_blocked"}`},
	}
	srv := newTestServerWithStream(t, &mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "unknown stream error")
}

func TestRoutes_SendMessage_NoStreamHandler_Returns503(t *testing.T) {
	// Verify runtime behavior: when no stream handler is configured, POST /api/v1/chat
	// must return 503 with a Retry-After header.
	srv := newTestServerWithData(t) // StreamHandler intentionally omitted

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "5", w.Header().Get("Retry-After"))
}

func TestRoutes_SendMessage_OpenAPIIncludes503(t *testing.T) {
	// Verify the OpenAPI spec declares 503 as a valid response for send-message.
	// handleSendMessage returns 503 when the stream handler is nil; the Errors slice
	// must include StatusServiceUnavailable so the generated spec reflects reality.
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var spec struct {
		Paths map[string]map[string]struct {
			OperationID string         `json:"operationId"`
			Responses   map[string]any `json:"responses"`
		} `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &spec))

	post, ok := spec.Paths["/api/v1/chat"]["post"]
	require.True(t, ok, "POST /api/v1/chat must be in the OpenAPI spec")
	assert.Equal(t, "send-message", post.OperationID)
	assert.Contains(t, post.Responses, "503",
		"send-message must declare 503 Service Unavailable in its OpenAPI responses")
}

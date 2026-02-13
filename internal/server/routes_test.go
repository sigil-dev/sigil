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
	"testing"

	"github.com/sigil-dev/sigil/internal/server"
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
	return nil, fmt.Errorf("workspace %q not found", id)
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
	return nil, fmt.Errorf("plugin %q not found", name)
}

func (m *mockPluginService) Reload(_ context.Context, name string) error {
	if name == "anthropic" {
		return nil
	}
	return fmt.Errorf("plugin %q not found", name)
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
	return nil, fmt.Errorf("session %q not found", sessionID)
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

func TestRoutes_SendMessage(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "text_delta", Data: `{"text":" world"}`},
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
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Hello world", resp.Content)
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

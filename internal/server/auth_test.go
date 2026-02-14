// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTokenValidator is a test double for the TokenValidator interface.
type mockTokenValidator struct {
	users map[string]*server.AuthenticatedUser
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, token string) (*server.AuthenticatedUser, error) {
	if user, ok := m.users[token]; ok {
		return user, nil
	}
	return nil, sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "invalid token")
}

// forbiddenTokenValidator always returns CodeServerAuthForbidden (simulates revoked tokens).
type forbiddenTokenValidator struct{}

func (v *forbiddenTokenValidator) ValidateToken(_ context.Context, _ string) (*server.AuthenticatedUser, error) {
	return nil, sigilerr.New(sigilerr.CodeServerAuthForbidden, "token revoked")
}

func newValidatorWithToken(token, userID, name string, permissions []string) server.TokenValidator {
	return &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			token: {
				ID:          userID,
				Name:        name,
				Permissions: permissions,
			},
		},
	}
}

func TestAuthMiddleware_PublicEndpointsSkipAuth(t *testing.T) {
	publicPaths := []string{"/health", "/openapi.json", "/openapi.yaml"}

	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			srv, err := server.New(server.Config{
				ListenAddr:     "127.0.0.1:0",
				TokenValidator: newValidatorWithToken("valid-token", "admin", "Admin", []string{"*"}),
			})
			require.NoError(t, err)

			// Request WITHOUT auth header to a public endpoint.
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			// /health returns 200; /openapi.yaml may return 404 if not registered,
			// but the key assertion is that it does NOT return 401.
			assert.NotEqual(t, http.StatusUnauthorized, w.Code, "public path %s should not require auth", path)
		})
	}
}

func TestAuthMiddleware_MissingAuthHeader_Returns401(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: newValidatorWithToken("valid-token", "admin", "Admin", []string{"*"}),
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "authorization header required")
}

func TestAuthMiddleware_InvalidBearerFormat_Returns401(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: newValidatorWithToken("valid-token", "admin", "Admin", []string{"*"}),
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	tests := []struct {
		name  string
		value string
	}{
		{"no prefix", "just-a-token"},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer lowercase", "bearer valid-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
			req.Header.Set("Authorization", tt.value)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code, "auth header %q should be rejected", tt.value)
		})
	}
}

func TestAuthMiddleware_InvalidToken_Returns401(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: newValidatorWithToken("valid-token", "admin", "Admin", []string{"*"}),
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ValidToken_InjectsUser(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: newValidatorWithToken("sk-test-123", "user-1", "Sean", []string{"*"}),
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.Header.Set("Authorization", "Bearer sk-test-123")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_ValidToken_UserInContext(t *testing.T) {
	validator := newValidatorWithToken("sk-test-123", "user-1", "Sean", []string{"admin:*"})

	// Build a handler that checks context for the authenticated user.
	var capturedUser *server.AuthenticatedUser
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedUser = server.UserFromContext(r.Context())
	})

	mw := server.NewAuthMiddleware(validator, []string{})
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer sk-test-123")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	require.NotNil(t, capturedUser, "user must be injected into context")
	assert.Equal(t, "user-1", capturedUser.ID)
	assert.Equal(t, "Sean", capturedUser.Name)
	assert.Equal(t, []string{"admin:*"}, capturedUser.Permissions)
}

func TestAuthMiddleware_Disabled_WhenValidatorNil(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		// No TokenValidator — auth disabled.
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	// Request WITHOUT auth header should pass through.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_ForbiddenToken_Returns403(t *testing.T) {
	// A validator that returns CodeServerAuthForbidden (e.g., revoked token).
	forbiddenValidator := &forbiddenTokenValidator{}
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: forbiddenValidator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.Header.Set("Authorization", "Bearer revoked-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "forbidden")
}

func TestUserFromContext_NilWhenNoUser(t *testing.T) {
	user := server.UserFromContext(context.Background())
	assert.Nil(t, user)
}

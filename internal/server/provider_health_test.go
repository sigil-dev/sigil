// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProviderService implements server.ProviderService for testing.
type mockProviderService struct {
	healthMap map[string]*server.ProviderHealthDetail
}

func (m *mockProviderService) GetHealth(_ context.Context, name string) (*server.ProviderHealthDetail, error) {
	if detail, ok := m.healthMap[name]; ok {
		return detail, nil
	}
	return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "provider %q not found", name)
}

func newTestServerWithProviders(t *testing.T, ps server.ProviderService, validator ...server.TokenValidator) *server.Server {
	t.Helper()
	svc := server.NewServicesForTest(
		&mockWorkspaceService{},
		&mockPluginService{},
		&mockSessionService{},
		&mockUserService{},
		ps,
	)
	cfg := server.Config{
		ListenAddr: "127.0.0.1:0",
		Services:   svc,
	}
	if len(validator) > 0 {
		cfg.TokenValidator = validator[0]
	}
	srv, err := server.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})
	return srv
}

func TestRoutes_GetProviderHealth_Healthy(t *testing.T) {
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{
			"anthropic": {
				Provider: "anthropic",
				Message:  "ok",
				Metrics:  health.Metrics{Available: true, FailureCount: 0},
			},
		},
	}
	srv := newTestServerWithProviders(t, ps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp server.ProviderHealthDetail
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, "anthropic", resp.Provider)
	assert.Equal(t, int64(0), resp.FailureCount)
	assert.Nil(t, resp.LastFailureAt)
	assert.Nil(t, resp.CooldownUntil)
}

func TestRoutes_GetProviderHealth_Unhealthy(t *testing.T) {
	failTime := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	cooldownEnd := failTime.Add(30 * time.Second)
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{
			"openai": {
				Provider: "openai",
				Message:  "ok",
				Metrics: health.Metrics{
					Available:     false,
					FailureCount:  3,
					LastFailureAt: &failTime,
					CooldownUntil: &cooldownEnd,
				},
			},
		},
	}
	srv := newTestServerWithProviders(t, ps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/openai/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp server.ProviderHealthDetail
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Available)
	assert.Equal(t, "openai", resp.Provider)
	assert.Equal(t, int64(3), resp.FailureCount)
	require.NotNil(t, resp.LastFailureAt)
	assert.Equal(t, failTime.UTC(), resp.LastFailureAt.UTC())
	require.NotNil(t, resp.CooldownUntil)
	assert.Equal(t, cooldownEnd.UTC(), resp.CooldownUntil.UTC())
}

func TestRoutes_GetProviderHealth_NotFound(t *testing.T) {
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{},
	}
	srv := newTestServerWithProviders(t, ps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/nonexistent/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoutes_GetProviderHealth_Unauthenticated(t *testing.T) {
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{
			"anthropic": {Provider: "anthropic", Message: "ok", Metrics: health.Metrics{Available: true}},
		},
	}

	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:*"}),
		},
	}

	srv := newTestServerWithProviders(t, ps, validator)

	// No Authorization header — auth is enabled, so 401 is expected.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRoutes_GetProviderHealth_RequiresAdmin(t *testing.T) {
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{
			"anthropic": {Provider: "anthropic", Message: "ok", Metrics: health.Metrics{Available: true}},
		},
	}

	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Regular User", []string{"workspace:read"}),
		},
	}

	srv := newTestServerWithProviders(t, ps, validator)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestRoutes_GetProviderHealth_AdminWildcardSucceeds(t *testing.T) {
	ps := &mockProviderService{
		healthMap: map[string]*server.ProviderHealthDetail{
			"anthropic": {Provider: "anthropic", Message: "ok", Metrics: health.Metrics{Available: true}},
		},
	}

	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:*"}),
		},
	}

	srv := newTestServerWithProviders(t, ps, validator)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "anthropic")
}

func TestRoutes_GetProviderHealth_NotRegistered_NoProviderService(t *testing.T) {
	// When no ProviderService is configured, the endpoint should not be
	// registered, resulting in a 404 from the router.
	srv := newTestServerWithData(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// errProviderService is a ProviderService stub that always returns the given error from GetHealth.
type errProviderService struct {
	err error
}

func (e *errProviderService) GetHealth(_ context.Context, _ string) (*server.ProviderHealthDetail, error) {
	return nil, e.err
}

func TestRoutes_GetProviderHealth_UpstreamError(t *testing.T) {
	ps := &errProviderService{
		err: fmt.Errorf("timeout"),
	}
	srv := newTestServerWithProviders(t, ps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers/anthropic/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal server error")
}

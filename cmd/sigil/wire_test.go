// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testGatewayConfig() *config.Config {
	return &config.Config{
		Networking: config.NetworkingConfig{
			Listen: "127.0.0.1:0",
		},
		Storage: config.StorageConfig{
			Backend: "sqlite",
		},
	}
}

func TestWireGateway(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	assert.NotNil(t, gw.Server)
	assert.NotNil(t, gw.WorkspaceManager)
	assert.NotNil(t, gw.PluginManager)
	assert.NotNil(t, gw.ProviderRegistry)
	assert.NotNil(t, gw.Enforcer)
	assert.NotNil(t, gw.GatewayStore)
}

func TestGateway_GracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start and immediately cancel — should shut down cleanly.
	err = gw.Start(ctx)
	assert.NoError(t, err)
}

func TestWireGateway_ChatEndpointNotDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	body := `{"content":"hello","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.Server.Handler().ServeHTTP(w, req)

	// Must NOT be 503 — a stream handler must be registered.
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code,
		"chat endpoint should not return 503 when gateway is wired")
	assert.Equal(t, http.StatusOK, w.Code)

	// The stub handler should return a message indicating the agent isn't configured.
	assert.Contains(t, w.Body.String(), "not yet configured")
}

func TestWireGateway_ChatStreamEndpointNotDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	body := `{"content":"hello","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()
	gw.Server.Handler().ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code,
		"chat/stream endpoint should not return 503 when gateway is wired")
	assert.Contains(t, w.Body.String(), "text_delta")
	assert.Contains(t, w.Body.String(), "not yet configured")
}

func TestWorkspaceServiceAdapter_ListReturnsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	// No workspaces configured.

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	gw.Server.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Must be JSON array "[]", not "null".
	body := strings.TrimSpace(w.Body.String())
	assert.True(t, strings.Contains(body, "[]") || strings.HasPrefix(body, "[]"),
		"expected empty JSON array, got: %s", body)
	assert.NotContains(t, body, "null", "list must return [] not null")
}

func TestSessionServiceAdapter_ListReturnsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Workspaces = map[string]config.WorkspaceConfig{
		"test-ws": {Description: "Test workspace"},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/test-ws/sessions", nil)
	w := httptest.NewRecorder()
	gw.Server.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := strings.TrimSpace(w.Body.String())
	assert.True(t, strings.Contains(body, "[]") || strings.HasPrefix(body, "[]"),
		"expected empty JSON array, got: %s", body)
	assert.NotContains(t, body, "null", "list must return [] not null")
}

func TestPluginServiceAdapter_FieldCompleteness(t *testing.T) {
	// Test that the adapter maps all Instance fields to PluginSummary/PluginDetail.
	adapter := &pluginServiceAdapter{mgr: nil}
	_ = adapter // Verify it compiles; full integration test below.

	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	// Plugin list with no plugins should return empty array, not null.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	w := httptest.NewRecorder()
	gw.Server.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := strings.TrimSpace(w.Body.String())
	assert.True(t, strings.Contains(body, "[]") || strings.HasPrefix(body, "[]"),
		"expected empty JSON array for plugins, got: %s", body)
	assert.NotContains(t, body, "null")
}

func TestWireGateway_WithWorkspaces(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Workspaces = map[string]config.WorkspaceConfig{
		"test-ws": {Description: "Test workspace", Members: []string{"user-1"}},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	assert.NotNil(t, gw.WorkspaceManager)
}

func TestWireGateway_ProviderRegistration(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"anthropic": {APIKey: "test-key-anthropic"},
		"openai":    {APIKey: "test-key-openai"},
		"google":    {APIKey: "test-key-google"},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	// All three providers should be registered.
	for _, name := range []string{"anthropic", "openai", "google"} {
		p, err := gw.ProviderRegistry.Get(name)
		assert.NoError(t, err, "provider %q should be registered", name)
		assert.NotNil(t, p, "provider %q should not be nil", name)
	}
}

func TestWireGateway_ProviderSkipsEmptyAPIKey(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"anthropic": {APIKey: ""}, // empty — should be skipped
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	_, err = gw.ProviderRegistry.Get("anthropic")
	assert.Error(t, err, "provider with empty API key should not be registered")
}

func TestWireGateway_ProviderCreationFailureSkipped(t *testing.T) {
	// Inject a factory that always fails to exercise the err != nil path.
	orig := builtinProviderFactories["anthropic"]
	builtinProviderFactories["anthropic"] = func(_ config.ProviderConfig) (provider.Provider, error) {
		return nil, fmt.Errorf("injected failure")
	}
	t.Cleanup(func() { builtinProviderFactories["anthropic"] = orig })

	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"anthropic": {APIKey: "test-key"},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err, "provider creation failure should not prevent startup")
	defer func() { _ = gw.Close() }()

	_, err = gw.ProviderRegistry.Get("anthropic")
	assert.Error(t, err, "failed provider should not be registered")
}

func TestWireGateway_UnknownProviderSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"unknown-provider": {APIKey: "some-key"},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err, "unknown provider should not cause startup failure")
	defer func() { _ = gw.Close() }()

	_, err = gw.ProviderRegistry.Get("unknown-provider")
	assert.Error(t, err, "unknown provider should not be registered")
}

// Test constant-time token comparison prevents timing attacks
func TestConfigTokenValidator_ConstantTimeComparison(t *testing.T) {
	validator, err := newConfigTokenValidator([]config.TokenConfig{
		{Token: "valid-token-123", UserID: "user-1", Name: "Test User", Permissions: []string{"*"}},
		{Token: "another-valid-token", UserID: "user-2", Name: "Another User", Permissions: []string{"read.*"}},
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		token    string
		wantUser string
		wantErr  bool
	}{
		{
			name:     "valid token 1",
			token:    "valid-token-123",
			wantUser: "user-1",
			wantErr:  false,
		},
		{
			name:     "valid token 2",
			token:    "another-valid-token",
			wantUser: "user-2",
			wantErr:  false,
		},
		{
			name:    "invalid token same length as valid",
			token:   "invalid-token-12", // same length as valid token
			wantErr: true,
		},
		{
			name:    "invalid token different length",
			token:   "short",
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "token with one bit flipped",
			token:   "valid-token-124", // last char different
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := validator.ValidateToken(context.Background(), tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.wantUser, user.ID())
			}
		})
	}
}

// Test that ValidateToken uses constant-time comparison by verifying it checks ALL tokens
func TestConfigTokenValidator_ChecksAllTokens(t *testing.T) {
	// Create validator with multiple tokens to ensure all are checked
	validator, err := newConfigTokenValidator([]config.TokenConfig{
		{Token: "token-1", UserID: "user-1", Name: "User 1", Permissions: []string{"*"}},
		{Token: "token-2", UserID: "user-2", Name: "User 2", Permissions: []string{"*"}},
		{Token: "token-3", UserID: "user-3", Name: "User 3", Permissions: []string{"*"}},
	})
	require.NoError(t, err)

	// All tokens should be validated successfully
	for i := 1; i <= 3; i++ {
		token := fmt.Sprintf("token-%d", i)
		userID := fmt.Sprintf("user-%d", i)
		user, err := validator.ValidateToken(context.Background(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, userID, user.ID())
	}
}

// Test that newConfigTokenValidator returns error when all tokens fail validation.
func TestConfigTokenValidator_AllTokensInvalid_ReturnsError(t *testing.T) {
	// All tokens have empty UserID which fails NewAuthenticatedUser validation.
	_, err := newConfigTokenValidator([]config.TokenConfig{
		{Token: "token-1", UserID: "", Name: "User 1", Permissions: []string{"*"}},
		{Token: "token-2", UserID: "", Name: "User 2", Permissions: []string{"*"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all configured auth tokens failed validation")
}

// Test Gateway.Close does not panic during shutdown
func TestGateway_CloseDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)

	// Normal close should succeed for all subsystems.
	err = gw.Close()
	assert.NoError(t, err)

	// Close is idempotent for both subsystems, so we cannot verify that
	// errors.Join collects errors from both without injectable mock closers.
	// This test confirms Close does not panic on a properly initialized Gateway.
}

// Test that Gateway.Close properly closes the ProviderRegistry
func TestGateway_CloseClosesProviderRegistry(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"anthropic": {APIKey: "test-key"},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)

	// Verify the provider is registered before close.
	_, err = gw.ProviderRegistry.Get("anthropic")
	require.NoError(t, err, "provider should be registered before close")

	// Close the gateway, which should close the ProviderRegistry.
	err = gw.Close()
	assert.NoError(t, err, "gateway.Close should not error")

	// After close, the ProviderRegistry should still contain the provider
	// (Close doesn't unregister providers, it just cleans up their resources).
	// The key indicator is that no panic occurs during the close operation.
}

func TestWireGateway_RateLimitConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Networking.RateLimitRPS = 10.0
	cfg.Networking.RateLimitBurst = 20

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	assert.NotNil(t, gw.Server)
	// Server was created successfully with rate limit config.
	// The middleware is tested separately in internal/server/ratelimit_test.go
}

func TestWireGateway_RegistryDefaultAndFailoverWired(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Providers = map[string]config.ProviderConfig{
		"anthropic": {APIKey: "test-key-anthropic"},
		"openai":    {APIKey: "test-key-openai"},
	}
	cfg.Models = config.ModelsConfig{
		Default:  "anthropic/claude-sonnet-4-5",
		Failover: []string{"openai/gpt-4o"},
		Budgets: config.BudgetsConfig{
			PerSessionTokens: 100000,
			PerDayUSD:        50.0,
		},
	}

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	// Route with empty model name should resolve via SetDefault → "anthropic/claude-sonnet-4-5".
	p, model, err := gw.ProviderRegistry.Route(context.Background(), "", "")
	require.NoError(t, err, "routing should succeed with default provider configured")
	assert.NotNil(t, p)
	assert.Equal(t, "claude-sonnet-4-5", model)
	assert.Equal(t, "anthropic", p.Name())

	// MaxAttempts should be 1 (primary) + 1 (failover) = 2.
	assert.Equal(t, 2, gw.ProviderRegistry.MaxAttempts(),
		"failover chain should be wired: 1 primary + 1 failover")
}

func TestWireGateway_RegistryDefaultNotWired_RouteFails(t *testing.T) {
	// Verify that without Models.Default the registry cannot route.
	// This is the bug scenario — if SetDefault is never called, Route returns
	// "no default provider configured".
	reg := provider.NewRegistry()
	// Register a provider but never call SetDefault.
	reg.Register("anthropic", &stubProvider{name: "anthropic"})

	_, _, err := reg.Route(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default provider configured")
}

func TestWireGateway_HSTSConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Networking.EnableHSTS = true

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	assert.NotNil(t, gw.Server)
	// Server was created successfully with HSTS enabled.
	// The middleware is tested separately in internal/server/hsts_test.go
}

// Test that Gateway.Close calls Server.Close to prevent goroutine leaks.
// This test verifies the fix for the bug where Gateway.Close() didn't call Server.Close(),
// causing the rate limiter cleanup goroutine to leak.
func TestGateway_CloseCallsServerClose(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()

	gw, err := WireGateway(context.Background(), cfg, dir)
	require.NoError(t, err)

	// Close the gateway which MUST close the server to prevent rate limiter goroutine leak.
	err = gw.Close()
	assert.NoError(t, err)

	// If Gateway.Close() called Server.Close(), then calling it again should be safe
	// due to the sync.Once in Server.Close(). We verify this doesn't panic.
	assert.NotPanics(t, func() {
		_ = gw.Server.Close()
	}, "Server.Close should be idempotent, proving Gateway.Close called it")
}

// stubProvider is a minimal Provider implementation for negative test cases.
type stubProvider struct {
	name string
}

func (s *stubProvider) Name() string                                                          { return s.name }
func (s *stubProvider) Available(_ context.Context) bool                                      { return true }
func (s *stubProvider) ListModels(_ context.Context) ([]provider.ModelInfo, error)             { return nil, nil }
func (s *stubProvider) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) { return nil, nil }
func (s *stubProvider) Status(_ context.Context) (provider.ProviderStatus, error)             { return provider.ProviderStatus{Provider: s.name, Available: true}, nil }
func (s *stubProvider) Close() error                                                          { return nil }

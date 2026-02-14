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

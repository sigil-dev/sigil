// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/config"
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

	gw, err := WireGateway(cfg, dir)
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

	gw, err := WireGateway(cfg, dir)
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

	gw, err := WireGateway(cfg, dir)
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

	gw, err := WireGateway(cfg, dir)
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

func TestWireGateway_WithWorkspaces(t *testing.T) {
	dir := t.TempDir()
	cfg := testGatewayConfig()
	cfg.Workspaces = map[string]config.WorkspaceConfig{
		"test-ws": {Description: "Test workspace", Members: []string{"user-1"}},
	}

	gw, err := WireGateway(cfg, dir)
	require.NoError(t, err)
	defer func() { _ = gw.Close() }()

	assert.NotNil(t, gw.WorkspaceManager)
}

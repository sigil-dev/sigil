// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)
	return srv
}

func TestServer_New(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)
}

func TestServer_New_EmptyListenAddr(t *testing.T) {
	_, err := server.New(server.Config{})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid), "expected CodeServerConfigInvalid, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "listen address is required")
}

func TestServer_HealthEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestServer_OpenAPISpec(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "openapi")
	assert.Contains(t, w.Body.String(), "openapi")
}

func TestServer_OpenAPISpecIncludesChatStream(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "/api/v1/chat/stream", "OpenAPI spec must include SSE streaming endpoint path")
	assert.Contains(t, body, "chat-stream", "OpenAPI spec must include chat-stream operation ID")
}

func TestServer_CORSHeaders(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_GracefulShutdown(t *testing.T) {
	srv := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for context cancellation to trigger shutdown.
	<-ctx.Done()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down within timeout")
	}
}

func TestServer_SecurityHeaders(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "0", w.Header().Get("X-XSS-Protection"))
}

func TestServer_CORSOrigins_FromConfig(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:  "127.0.0.1:0",
		CORSOrigins: []string{"https://app.example.com", "https://admin.example.com"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_CORSOrigins_DefaultsToLocalhost(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_CORSOrigins_WildcardRejected(t *testing.T) {
	_, err := server.New(server.Config{
		ListenAddr:  "127.0.0.1:0",
		CORSOrigins: []string{"*"},
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
	assert.Contains(t, err.Error(), "CORS origin")
}

func TestServer_HSTSHeader_WhenEnabled(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		EnableHSTS: true,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=")
}

func TestServer_HSTSHeader_DisabledByDefault(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

func TestServer_RateLimiterBeforeAuth(t *testing.T) {
	// Create a server with auth enabled and rate limiting enabled.
	// The rate limiter should block requests BEFORE auth checks them,
	// preventing unauthenticated brute-force attacks.
	validator := newValidatorWithToken("valid-token", "user1", "Test User", nil)

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		RateLimit: server.RateLimitConfig{
			RequestsPerSecond: 100,
			Burst:             2, // allow only 2 requests in burst
		},
	})
	require.NoError(t, err)

	// Send requests WITHOUT a valid token (unauthenticated brute-force).
	// If rate limiter is before auth: after burst, we get 429.
	// If rate limiter is after auth: auth rejects first and we never get rate limited.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		// No Authorization header — unauthenticated request
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		// These should get 401 (auth failure) since they pass rate limiter
		assert.Equal(t, http.StatusUnauthorized, w.Code, "request %d should get 401 (auth rejected)", i)
	}

	// Third request: burst exhausted. Rate limiter should reject BEFORE auth.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code,
		"unauthenticated request should be rate-limited (429), not auth-rejected (401) — "+
			"rate limiter must run before auth middleware")
}

func TestServer_BehindProxy_RequiresTrustedProxies(t *testing.T) {
	_, err := server.New(server.Config{
		ListenAddr:  "127.0.0.1:0",
		BehindProxy: true,
		// No TrustedProxies configured
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trusted_proxies must be configured")
}

func TestServer_BehindProxy_WithTrustedProxies(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		BehindProxy:    true,
		TrustedProxies: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)
}

func TestServer_BehindProxy_InvalidCIDR(t *testing.T) {
	_, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		BehindProxy:    true,
		TrustedProxies: []string{"not-a-cidr"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trusted proxy CIDR")
}

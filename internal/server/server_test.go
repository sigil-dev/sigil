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
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})
	return srv
}

func TestServer_New(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()
	assert.NotNil(t, srv)
}

func TestServer_New_EmptyListenAddr(t *testing.T) {
	_, err := server.New(server.Config{})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid), "expected CodeServerConfigInvalid, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "listen address is required")
}

func TestServer_New_InvalidChatRateLimitConfig(t *testing.T) {
	_, err := server.New(server.Config{
		ListenAddr:               "127.0.0.1:0",
		ChatRateLimitEnabled:     true,
		ChatRateLimitRPM:         10,
		ChatRateLimitBurst:       0,
		ChatMaxConcurrentStreams: 1,
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid), "expected CodeServerConfigInvalid, got %s", sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "chat rate limit burst must be positive")
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
	srv, err := server.New(server.Config{
		ListenAddr:  "127.0.0.1:0",
		CORSOrigins: []string{"http://localhost:5173"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})

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
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_CORSOrigins_NoConfig_LocalhostUsesDevDefault(t *testing.T) {
	// When running on localhost with no CORS origins configured, dev-mode default is used
	srv := newTestServer(t) // no CORSOrigins configured, ListenAddr is 127.0.0.1:0

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// With dev-mode default for localhost, the origin should be allowed
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestServer_CORSOrigins_NoConfig_NonLocalhostRejectsAll(t *testing.T) {
	// When running on non-localhost with no CORS origins configured, reject all
	srv, err := server.New(server.Config{
		ListenAddr: "192.168.1.100:8080", // non-localhost address
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Non-localhost without explicit CORS config should reject all origins
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
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
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()

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

func TestServer_CSPHeader_IsPresent(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	csp := w.Header().Get("Content-Security-Policy")
	assert.NotEmpty(t, csp)
	// Verify key directives are present
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	// connect-src should only include 'self' by default; DevCSPConnectSrc is empty in tests.
	assert.Contains(t, csp, "connect-src 'self'")
	assert.NotContains(t, csp, "localhost:18789")
}

func TestServer_CSPHeader_DevCSPConnectSrc_AppendedToConnectSrc(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr:       "127.0.0.1:0",
		DevCSPConnectSrc: "http://localhost:18789",
	})
	require.NoError(t, err)
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "connect-src 'self' http://localhost:18789",
		"CSP connect-src should include the configured DevCSPConnectSrc value")
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
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()

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
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	}()
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

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     server.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
			},
			wantErr: false,
		},
		{
			name: "valid config with all fields",
			cfg: server.Config{
				ListenAddr:   "127.0.0.1:8080",
				CORSOrigins:  []string{"https://example.com"},
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 20 * time.Second,
				EnableHSTS:   true,
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             5,
				},
			},
			wantErr: false,
		},
		{
			name: "empty listen address",
			cfg: server.Config{
				ListenAddr: "",
			},
			wantErr: true,
			errMsg:  "listen address is required",
		},
		{
			name: "CORS wildcard rejected",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				CORSOrigins: []string{"*"},
			},
			wantErr: true,
			errMsg:  "CORS origin",
		},
		{
			name: "behind proxy without trusted proxies",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				BehindProxy: true,
			},
			wantErr: true,
			errMsg:  "trusted_proxies must be configured",
		},
		{
			name: "behind proxy with trusted proxies",
			cfg: server.Config{
				ListenAddr:     "127.0.0.1:8080",
				BehindProxy:    true,
				TrustedProxies: []string{"10.0.0.0/8"},
			},
			wantErr: false,
		},
		{
			name: "invalid trusted proxy CIDR",
			cfg: server.Config{
				ListenAddr:     "127.0.0.1:8080",
				BehindProxy:    true,
				TrustedProxies: []string{"not-a-cidr"},
			},
			wantErr: true,
			errMsg:  "invalid trusted proxy CIDR",
		},
		{
			name: "invalid rate limit config",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             0, // invalid: burst must be positive when rate is set
				},
			},
			wantErr: true,
			errMsg:  "burst must be positive",
		},
		{
			name: "applies default timeouts",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				// ReadTimeout and WriteTimeout not set
			},
			wantErr: false,
		},
		{
			name: "valid DevCSPConnectSrc",
			cfg: server.Config{
				ListenAddr:       "127.0.0.1:8080",
				DevCSPConnectSrc: "http://localhost:18789",
			},
			wantErr: false,
		},
		{
			name: "DevCSPConnectSrc with newline rejected",
			cfg: server.Config{
				ListenAddr:       "127.0.0.1:8080",
				DevCSPConnectSrc: "http://localhost:18789\nevil-header: injected",
			},
			wantErr: true,
			errMsg:  "DevCSPConnectSrc must not contain CR, LF, or semicolons",
		},
		{
			name: "DevCSPConnectSrc with semicolon rejected",
			cfg: server.Config{
				ListenAddr:       "127.0.0.1:8080",
				DevCSPConnectSrc: "http://localhost:18789; script-src 'unsafe-eval'",
			},
			wantErr: true,
			errMsg:  "DevCSPConnectSrc must not contain CR, LF, or semicolons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the test case
			cfg := tt.cfg
			hadDefaultReadTimeout := cfg.ReadTimeout == 0
			hadDefaultWriteTimeout := cfg.WriteTimeout == 0

			cfg.ApplyDefaults()
			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				// Verify defaults are applied
				if hadDefaultReadTimeout {
					assert.Equal(t, 30*time.Second, cfg.ReadTimeout, "ReadTimeout should have default applied")
				}
				if hadDefaultWriteTimeout {
					assert.Equal(t, 60*time.Second, cfg.WriteTimeout, "WriteTimeout should have default applied")
				}
			}
		})
	}
}

func TestConfig_Validate_AppliesDefaults(t *testing.T) {
	cfg := server.Config{
		ListenAddr: "127.0.0.1:8080",
		// No timeouts specified
	}

	cfg.ApplyDefaults()
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout, "ReadTimeout should have default")
	assert.Equal(t, 60*time.Second, cfg.WriteTimeout, "WriteTimeout should have default")
}

func TestConfig_Validate_Boundary(t *testing.T) {
	tests := []struct {
		name    string
		cfg     server.Config
		wantErr bool
		errMsg  string
	}{
		// ListenAddr boundary: whitespace-only is not empty but will fail at net.Listen time,
		// not at Validate(). Validate only checks for empty string.
		{
			name: "listen addr with port 0 accepted by validation",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:0",
			},
			wantErr: false,
		},
		{
			name: "listen addr with max port accepted by validation",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:65535",
			},
			wantErr: false,
		},
		// Note: server.Config.ListenAddr is a string parsed by net.Listen, not an int port.
		// Invalid ports like 65536 or -1 are caught by net.Listen in Start(), not Validate().
		// These tests confirm Validate() does not reject them (it only checks for empty).
		{
			name: "listen addr with out-of-range port passes validation",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:65536",
			},
			wantErr: false,
		},
		{
			name: "listen addr with negative port passes validation",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:-1",
			},
			wantErr: false,
		},

		// CORS boundary: wildcard mixed with valid origins still rejected
		{
			name: "CORS wildcard among valid origins rejected",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				CORSOrigins: []string{"https://example.com", "*"},
			},
			wantErr: true,
			errMsg:  "CORS origin",
		},
		{
			name: "CORS single valid origin accepted",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				CORSOrigins: []string{"https://example.com"},
			},
			wantErr: false,
		},
		{
			name: "CORS empty slice accepted",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				CORSOrigins: []string{},
			},
			wantErr: false,
		},
		{
			name: "CORS nil slice accepted",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				CORSOrigins: nil,
			},
			wantErr: false,
		},

		// RateLimit boundary: smallest positive rate requires burst > 0
		{
			name: "rate limit smallest positive rate with zero burst rejected",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 0.001,
					Burst:             0,
				},
			},
			wantErr: true,
			errMsg:  "burst must be positive",
		},
		{
			name: "rate limit smallest positive rate with burst 1 accepted",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 0.001,
					Burst:             1,
				},
			},
			wantErr: false,
		},
		{
			name: "rate limit negative rate rejected",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: -0.001,
					Burst:             5,
				},
			},
			wantErr: true,
			errMsg:  "requests per second must not be negative",
		},
		{
			name: "rate limit zero rate with negative burst accepted (disabled)",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 0,
					Burst:             -1,
				},
			},
			wantErr: false,
		},
		{
			name: "rate limit max visitors boundary 1 accepted",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             5,
					MaxVisitors:       1,
				},
			},
			wantErr: false,
		},
		{
			name: "rate limit max visitors negative rejected",
			cfg: server.Config{
				ListenAddr: "127.0.0.1:8080",
				RateLimit: server.RateLimitConfig{
					RequestsPerSecond: 10,
					Burst:             5,
					MaxVisitors:       -1,
				},
			},
			wantErr: true,
			errMsg:  "max visitors must not be negative",
		},

		// BehindProxy boundary: empty CIDR string in list
		{
			name: "behind proxy with empty CIDR string in list",
			cfg: server.Config{
				ListenAddr:     "127.0.0.1:8080",
				BehindProxy:    true,
				TrustedProxies: []string{""},
			},
			wantErr: true,
			errMsg:  "trusted_proxies must contain at least one valid CIDR",
		},
		{
			name: "behind proxy with multiple CIDRs accepted",
			cfg: server.Config{
				ListenAddr:     "127.0.0.1:8080",
				BehindProxy:    true,
				TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
			wantErr: false,
		},
		{
			name: "behind proxy with mixed valid and invalid CIDR rejected",
			cfg: server.Config{
				ListenAddr:     "127.0.0.1:8080",
				BehindProxy:    true,
				TrustedProxies: []string{"10.0.0.0/8", "not-valid"},
			},
			wantErr: true,
			errMsg:  "invalid trusted proxy CIDR",
		},

		// Timeout boundary: custom timeouts preserved through ApplyDefaults
		{
			name: "custom read timeout preserved",
			cfg: server.Config{
				ListenAddr:  "127.0.0.1:8080",
				ReadTimeout: 1 * time.Millisecond,
			},
			wantErr: false,
		},
		{
			name: "custom write timeout preserved",
			cfg: server.Config{
				ListenAddr:   "127.0.0.1:8080",
				WriteTimeout: 1 * time.Millisecond,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid),
					"expected CodeServerConfigInvalid, got %s", sigilerr.CodeOf(err))
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_ApplyDefaults_PreservesCustomTimeouts(t *testing.T) {
	cfg := server.Config{
		ListenAddr:   "127.0.0.1:8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	cfg.ApplyDefaults()

	assert.Equal(t, 5*time.Second, cfg.ReadTimeout, "custom ReadTimeout should not be overwritten")
	assert.Equal(t, 10*time.Second, cfg.WriteTimeout, "custom WriteTimeout should not be overwritten")
}

func TestServer_CORSOrigins_DevDefault_LocalhostVariants(t *testing.T) {
	tests := []struct {
		name        string
		listenAddr  string
		expectCORS  bool
		description string
	}{
		{
			name:        "127.0.0.1 with port",
			listenAddr:  "127.0.0.1:8080",
			expectCORS:  true,
			description: "IPv4 localhost with port should use dev default",
		},
		{
			name:        "localhost with port",
			listenAddr:  "localhost:8080",
			expectCORS:  true,
			description: "localhost hostname with port should use dev default",
		},
		{
			name:        "::1 with port",
			listenAddr:  "[::1]:8080",
			expectCORS:  true,
			description: "IPv6 localhost with port should use dev default",
		},
		{
			name:        "0.0.0.0 with port",
			listenAddr:  "0.0.0.0:8080",
			expectCORS:  true,
			description: "0.0.0.0 (all interfaces) should use dev default",
		},
		{
			name:        ":: with port",
			listenAddr:  "[::]:8080",
			expectCORS:  true,
			description: ":: (all interfaces IPv6) should use dev default",
		},
		{
			name:        "192.168.1.100 with port",
			listenAddr:  "192.168.1.100:8080",
			expectCORS:  false,
			description: "non-localhost IP should not use dev default",
		},
		{
			name:        "example.com with port",
			listenAddr:  "example.com:8080",
			expectCORS:  false,
			description: "domain name should not use dev default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := server.New(server.Config{
				ListenAddr: tt.listenAddr,
				// No CORSOrigins configured
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				if err := srv.Close(); err != nil {
					t.Logf("srv.Close() in cleanup: %v", err)
				}
			})

			req := httptest.NewRequest(http.MethodOptions, "/api/v1/workspaces", nil)
			req.Header.Set("Origin", "http://localhost:5173")
			req.Header.Set("Access-Control-Request-Method", "GET")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if tt.expectCORS {
				assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"),
					"%s: should allow dev-mode origin", tt.description)
			} else {
				assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
					"%s: should reject cross-origin requests", tt.description)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimitMiddleware_Disabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Zero RequestsPerSecond disables rate limiting
	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 0,
		Burst:             10,
	})

	wrapped := middleware(handler)

	// Should pass through unlimited requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	}
}

func TestRateLimitMiddleware_WithinLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             5,
	})

	wrapped := middleware(handler)

	// First 5 requests (burst) should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		assert.Equal(t, "ok", w.Body.String())
	}
}

func TestRateLimitMiddleware_ExceedsLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             3,
	})

	wrapped := middleware(handler)

	ip := "192.168.1.1:12345"

	// First 3 requests (burst) should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
	}

	// 4th request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), "rate limit exceeded")
}

func TestRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             2,
	})

	wrapped := middleware(handler)

	ip1 := "192.168.1.1:12345"
	ip2 := "192.168.1.2:12345"

	// IP1: use up burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip1
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// IP1: next request rate limited
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = ip1
	w1 := httptest.NewRecorder()
	wrapped.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusTooManyRequests, w1.Code)

	// IP2: should still have full burst available
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip2
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "IP2 request %d should succeed", i)
	}
}

func TestRateLimitMiddleware_TokenRefill(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 10 requests per second = 1 token every 100ms
	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             2,
	})

	wrapped := middleware(handler)

	ip := "192.168.1.1:12345"

	// Use up burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// Next request should fail
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Wait 150ms (should refill ~1.5 tokens at 10 req/s)
	time.Sleep(150 * time.Millisecond)

	// Next request should succeed (token refilled)
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	w = httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "request should succeed after token refill")
}

func TestRateLimitMiddleware_RetryAfterHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             1,
	})

	wrapped := middleware(handler)

	ip := "192.168.1.1:12345"

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Second request rate limited
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	w = httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"), "Retry-After header should be set to 1 second")
}

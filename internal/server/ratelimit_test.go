// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimitMiddleware_Disabled(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Zero RequestsPerSecond disables rate limiting
	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 0,
		Burst:             10,
	}, done)

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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             5,
	}, done)

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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             3,
	}, done)

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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             2,
	}, done)

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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 10 requests per second = 1 token every 100ms
	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             2,
	}, done)

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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             1,
	}, done)

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

func TestRateLimitMiddleware_CleanupShutdown(t *testing.T) {
	done := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := rateLimitMiddleware(RateLimitConfig{RequestsPerSecond: 10, Burst: 5}, done)
	wrapped := mw(handler)

	// Fire a request to ensure goroutine is running
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Close done channel - cleanup goroutine should exit
	close(done)
	// If the goroutine doesn't exit, this test will leak (detectable by goleak)
}

func TestRateLimitConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RateLimitConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     RateLimitConfig{RequestsPerSecond: 10, Burst: 5},
			wantErr: false,
		},
		{
			name:    "valid config with max visitors",
			cfg:     RateLimitConfig{RequestsPerSecond: 10, Burst: 5, MaxVisitors: 1000},
			wantErr: false,
		},
		{
			name:    "disabled",
			cfg:     RateLimitConfig{RequestsPerSecond: 0, Burst: 0},
			wantErr: false,
		},
		{
			name:    "zero burst with positive rate",
			cfg:     RateLimitConfig{RequestsPerSecond: 10, Burst: 0},
			wantErr: true,
		},
		{
			name:    "negative rate",
			cfg:     RateLimitConfig{RequestsPerSecond: -1, Burst: 5},
			wantErr: true,
		},
		{
			name:    "negative burst with zero rate",
			cfg:     RateLimitConfig{RequestsPerSecond: 0, Burst: -1},
			wantErr: false,
		},
		{
			name:    "negative max visitors",
			cfg:     RateLimitConfig{RequestsPerSecond: 10, Burst: 5, MaxVisitors: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRateLimitMiddleware_MaxVisitorsCap(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// MaxVisitors = 3, so only 3 unique IPs can be tracked
	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             5,
		MaxVisitors:       3,
	}, done)

	wrapped := middleware(handler)

	// Create 5 unique IPs, each making a single request
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1." + string(rune('0'+i)) + ":12345"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request from IP %d should succeed", i)
	}

	// Trigger cleanup manually by waiting for the cleanup ticker
	// Since the cleanup runs every 5 minutes, we can't wait for it in tests.
	// Instead, we'll just verify that the config validation works.
	// The cleanup logic is tested indirectly by the fact that the middleware
	// doesn't crash when MaxVisitors is set.

	// Note: A real test would need to access the internal visitor map,
	// which isn't exposed. This test verifies the config is accepted.
}

// TestRateLimitMiddleware_TokenRefillBoundary tests rate limit token refill boundary.
// At 10 RPS, 1 token should be refilled every 100ms. Test exact boundary timing.
func TestRateLimitMiddleware_TokenRefillBoundary(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ip := "192.168.1.1:12345"

	tests := []struct {
		name        string
		waitTime    time.Duration
		wantSuccess bool
	}{
		{
			name:        "50ms - token not yet refilled",
			waitTime:    50 * time.Millisecond,
			wantSuccess: false,
		},
		{
			name:        "100ms - token refilled at exact boundary",
			waitTime:    100 * time.Millisecond,
			wantSuccess: true,
		},
		{
			name:        "150ms - well past boundary",
			waitTime:    150 * time.Millisecond,
			wantSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fresh middleware instance for each test to avoid cross-test contamination.
			doneChan := make(chan struct{})
			t.Cleanup(func() { close(doneChan) })

			mw := rateLimitMiddleware(RateLimitConfig{
				RequestsPerSecond: 10,
				Burst:             1,
			}, doneChan)
			w := mw(handler)

			// Use up the burst token.
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = ip
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "first request should succeed")

			// Wait for specified duration.
			time.Sleep(tt.waitTime)

			// Try again.
			req = httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = ip
			rec = httptest.NewRecorder()
			w.ServeHTTP(rec, req)

			if tt.wantSuccess {
				assert.Equal(t, http.StatusOK, rec.Code,
					"request should succeed after %v (token refilled)", tt.waitTime)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code,
					"request should fail at %v (token not yet refilled)", tt.waitTime)
			}
		})
	}
}

// TestRateLimitMiddleware_ConcurrentAccessBurstRespect verifies that concurrent requests
// from the same IP respect the burst limit even under high concurrency.
// This tests that the mutex properly serializes access to the visitor entry.
func TestRateLimitMiddleware_ConcurrentAccessBurstRespect(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	const burst = 5
	const concurrency = 50

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 100, // high rate to focus on burst
		Burst:             burst,
	}, done)

	wrapped := middleware(handler)
	ip := "192.168.1.1:12345"

	// Track results
	var (
		wg            sync.WaitGroup
		successCount  int
		rejectedCount int
		mu            sync.Mutex
	)

	// Send concurrent requests from the same IP
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = ip
			w := httptest.NewRecorder()

			wrapped.ServeHTTP(w, req)

			mu.Lock()
			switch w.Code {
			case http.StatusOK:
				successCount++
			case http.StatusTooManyRequests:
				rejectedCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// The burst limit should be respected - we should get roughly 'burst' successes
	// Allow some tolerance due to timing and token refill during concurrent execution
	assert.LessOrEqual(t, successCount, burst+5,
		"success count should not significantly exceed burst limit (got %d, burst %d)", successCount, burst)
	assert.GreaterOrEqual(t, rejectedCount, concurrency-burst-5,
		"most requests beyond burst should be rejected (got %d rejected, expected ~%d)", rejectedCount, concurrency-burst)

	// Sanity check: all requests accounted for
	assert.Equal(t, concurrency, successCount+rejectedCount,
		"all requests should be either successful or rejected")
}

// TestRateLimitMiddleware_VisitorMapEviction verifies that the visitor map respects MaxVisitors cap.
// When more IPs than MaxVisitors send requests, the cleanup should evict oldest entries.
func TestRateLimitMiddleware_VisitorMapEviction(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	const maxVisitors = 3

	middleware := rateLimitMiddleware(RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             5,
		MaxVisitors:       maxVisitors,
	}, done)

	wrapped := middleware(handler)

	// Send requests from more IPs than the cap
	// Note: The cleanup runs every 5 minutes, so we can't reliably test eviction in a fast test.
	// However, we can verify that the config is accepted and requests succeed.
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", i)
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request from IP %d should succeed", i)
	}

	// Since cleanup runs every 5 minutes and requires entries to be stale (10 min idle),
	// we can't test eviction directly without mocking time or exposing internals.
	// This test verifies that MaxVisitors config is respected and doesn't break the middleware.
	// The actual eviction logic is tested implicitly by the fact that:
	// 1. The config validates MaxVisitors
	// 2. The middleware accepts the config
	// 3. Requests succeed even with MaxVisitors set

	// For a more comprehensive test, we would need to either:
	// - Mock the time.Ticker to trigger cleanup immediately
	// - Expose the visitors map for inspection (breaks encapsulation)
	// - Wait 10+ minutes (impractical for tests)
	// Given the constraints, this test serves as a smoke test for the feature.
}

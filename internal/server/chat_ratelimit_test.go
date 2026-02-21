// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChatRateLimitConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     chatRateLimitConfig
		wantErr bool
	}{
		{
			name: "valid enabled config",
			cfg: chatRateLimitConfig{
				Enabled:              true,
				RequestsPerMinute:    30,
				Burst:                10,
				MaxConcurrentStreams: 5,
			},
			wantErr: false,
		},
		{
			name: "negative rpm",
			cfg: chatRateLimitConfig{
				Enabled:              true,
				RequestsPerMinute:    -1,
				Burst:                10,
				MaxConcurrentStreams: 5,
			},
			wantErr: true,
		},
		{
			name: "positive rpm requires burst",
			cfg: chatRateLimitConfig{
				Enabled:              true,
				RequestsPerMinute:    5,
				Burst:                0,
				MaxConcurrentStreams: 5,
			},
			wantErr: true,
		},
		{
			name: "enabled requires max concurrent streams",
			cfg: chatRateLimitConfig{
				Enabled:              true,
				RequestsPerMinute:    0,
				Burst:                0,
				MaxConcurrentStreams: 0,
			},
			wantErr: true,
		},
		{
			name: "disabled limiter with zero values is valid",
			cfg: chatRateLimitConfig{
				Enabled:              false,
				RequestsPerMinute:    0,
				Burst:                0,
				MaxConcurrentStreams: 0,
			},
			wantErr: false,
		},
		{
			name: "concurrency-only mode: rpm=0 burst=0 max_concurrent=5 is valid",
			cfg: chatRateLimitConfig{
				Enabled:              true,
				RequestsPerMinute:    0,
				Burst:                0,
				MaxConcurrentStreams: 5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.applyDefaults()
			err := cfg.validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestChatRateLimiterAllowRequest(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	limiter, err := newChatRateLimiter(chatRateLimitConfig{
		Enabled:              true,
		RequestsPerMinute:    60,
		Burst:                2,
		MaxConcurrentStreams: 2,
	}, done)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	key := "ip:192.0.2.10"
	assert.True(t, limiter.allowRequest(key))
	assert.True(t, limiter.allowRequest(key))
	assert.False(t, limiter.allowRequest(key), "third request should exceed burst")

	// 60 rpm => 1 token/sec, so waiting >1s should refill one token.
	time.Sleep(1100 * time.Millisecond)
	assert.True(t, limiter.allowRequest(key), "request should succeed after token refill")
}

func TestChatRateLimiterAcquireReleaseStream(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	limiter, err := newChatRateLimiter(chatRateLimitConfig{
		Enabled:              true,
		RequestsPerMinute:    0,
		Burst:                0,
		MaxConcurrentStreams: 2,
	}, done)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	key := "user:user-1"
	assert.True(t, limiter.acquireStream(key))
	assert.True(t, limiter.acquireStream(key))
	assert.False(t, limiter.acquireStream(key), "third stream should exceed max concurrent")

	limiter.releaseStream(key)
	assert.True(t, limiter.acquireStream(key), "acquire should succeed after release")

	// Double-release and missing key release should be safe no-op.
	limiter.releaseStream(key)
	limiter.releaseStream(key)
	limiter.releaseStream("user:missing")
}

func TestServerChatLimiterKey(t *testing.T) {
	srv := &Server{}

	user, err := NewAuthenticatedUser("user-1", "User 1", []string{"workspace:*"})
	require.NoError(t, err)

	ctxWithIP := context.WithValue(context.Background(), clientIPContextKey{}, "203.0.113.5")
	ctxWithUser := context.WithValue(ctxWithIP, authUserKey, user)

	tests := []struct {
		name        string
		ctx         context.Context
		wantKey     string
		wantKeyType string
	}{
		{
			name:        "ip present, no user",
			ctx:         ctxWithIP,
			wantKey:     "ip:203.0.113.5",
			wantKeyType: "ip",
		},
		{
			name:        "user present takes precedence over ip",
			ctx:         ctxWithUser,
			wantKey:     "user:user-1",
			wantKeyType: "user",
		},
		{
			name:        "no user, no ip falls back to unknown",
			ctx:         context.Background(),
			wantKey:     "ip:unknown",
			wantKeyType: "ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, keyType := srv.chatLimiterKey(tt.ctx)
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantKeyType, keyType)
		})
	}
}

func TestChatRateLimiter_ConcurrentAccess(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	limiter, err := newChatRateLimiter(chatRateLimitConfig{
		Enabled:              true,
		RequestsPerMinute:    6000, // 100 rps, lots of headroom
		Burst:                100,
		MaxConcurrentStreams: 50,
		MaxKeys:              100,
	}, done)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := "user:concurrent-test"
				if limiter.allowRequest(key) {
					if limiter.acquireStream(key) {
						runtime.Gosched()
						limiter.releaseStream(key)
					}
				}
			}
		}()
	}
	wg.Wait()
	// If we reach here without the race detector firing, the mutex is sufficient
}

func TestChatRateLimiter_CleanupDoesNotEvictActiveStreams(t *testing.T) {
	// Build a limiter directly without starting the background goroutine so
	// we control when cleanup runs.  MaxKeys=1 means any map with 2 or more
	// entries is over-capacity and the eviction path fires.
	limiter := &chatRateLimiter{
		cfg: chatRateLimitConfig{
			Enabled:              true,
			RequestsPerMinute:    0,
			Burst:                0,
			MaxConcurrentStreams: 5,
			MaxKeys:              1,
		},
		visitors: make(map[string]*chatVisitorEntry),
	}

	old := time.Now().Add(-30 * time.Minute) // well past the 10-min stale threshold

	// Entry A: has an active stream — must NOT be evicted.
	keyA := "ip:192.0.2.1"
	limiter.visitors[keyA] = &chatVisitorEntry{
		lastSeen:     old,
		lastRefill:   old,
		activeStreams: 1,
	}

	// Entry B: no active stream, old lastSeen — eligible for eviction.
	keyB := "ip:192.0.2.2"
	limiter.visitors[keyB] = &chatVisitorEntry{
		lastSeen:     old,
		lastRefill:   old,
		activeStreams: 0,
	}

	// With MaxKeys=1 and 2 entries, the eviction path should remove the
	// oldest entry without an active stream (B) and protect A.
	limiter.RunCleanupNow()

	limiter.mu.Lock()
	_, aPresent := limiter.visitors[keyA]
	_, bPresent := limiter.visitors[keyB]
	limiter.mu.Unlock()

	assert.True(t, aPresent, "entry with activeStreams>0 must not be evicted by cleanup")
	assert.False(t, bPresent, "entry with activeStreams==0 must be evicted when over MaxKeys")
}

func TestChatRateLimiter_LRUEvictionProtectsActiveStreams(t *testing.T) {
	// Build a limiter directly without starting the background goroutine.
	// MaxKeys=1 means any map with 2 entries is over-capacity.
	limiter := &chatRateLimiter{
		cfg: chatRateLimitConfig{
			Enabled:              true,
			RequestsPerMinute:    0,
			Burst:                0,
			MaxConcurrentStreams: 5,
			MaxKeys:              1,
		},
		visitors: make(map[string]*chatVisitorEntry),
	}

	recentA := time.Now().Add(-1 * time.Minute) // newer of the two, well within 10-min stale threshold
	recentB := time.Now().Add(-2 * time.Minute) // older of the two, still well within 10-min stale threshold

	// Entry A: has an active stream, newer lastSeen — must NOT be evicted.
	keyA := "ip:192.0.2.1"
	limiter.visitors[keyA] = &chatVisitorEntry{
		lastSeen:     recentA,
		lastRefill:   recentA,
		activeStreams: 1,
	}

	// Entry B: no active stream, older lastSeen — LRU sorts it first, eligible for eviction.
	keyB := "ip:192.0.2.2"
	limiter.visitors[keyB] = &chatVisitorEntry{
		lastSeen:     recentB,
		lastRefill:   recentB,
		activeStreams: 0,
	}

	// Both entries are recent so the stale-threshold pass skips both.
	// With 2 entries and MaxKeys=1, the LRU eviction block must fire
	// and remove B (activeStreams==0) while protecting A (activeStreams>0).
	limiter.RunCleanupNow()

	limiter.mu.Lock()
	_, aPresent := limiter.visitors[keyA]
	_, bPresent := limiter.visitors[keyB]
	limiter.mu.Unlock()

	assert.True(t, aPresent, "entry with activeStreams>0 must not be evicted by LRU cap")
	assert.False(t, bPresent, "entry with activeStreams==0 must be evicted when over MaxKeys via LRU")
}

func TestClientIPContextMiddleware(t *testing.T) {
	mw := clientIPContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromContext(r.Context())
		_, _ = w.Write([]byte(ip))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:4567"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	assert.Equal(t, "198.51.100.7", w.Body.String())

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "198.51.100.8"
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, req2)
	assert.Equal(t, "ip:unparseable", w2.Body.String())
}

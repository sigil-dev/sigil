// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	ctxWithIP := context.WithValue(context.Background(), clientIPContextKey{}, "203.0.113.5")
	key, keyType := srv.chatLimiterKey(ctxWithIP)
	assert.Equal(t, "ip:203.0.113.5", key)
	assert.Equal(t, "ip", keyType)

	user, err := NewAuthenticatedUser("user-1", "User 1", []string{"workspace:*"})
	require.NoError(t, err)
	ctxWithUser := context.WithValue(ctxWithIP, authUserKey, user)
	key, keyType = srv.chatLimiterKey(ctxWithUser)
	assert.Equal(t, "user:user-1", key)
	assert.Equal(t, "user", keyType)
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
	assert.Equal(t, "198.51.100.8", w2.Body.String())
}

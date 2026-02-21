// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const chatRateLimitRetryAfter = "1"

type chatRateLimitConfig struct {
	Enabled              bool
	RequestsPerMinute    int
	Burst                int
	MaxConcurrentStreams int
	MaxKeys              int
}

func (c *chatRateLimitConfig) applyDefaults() {
	if c.MaxKeys == 0 {
		c.MaxKeys = 10000
	}
}

func (c *chatRateLimitConfig) validate() error {
	if c.RequestsPerMinute < 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"chat rate limit requests per minute must not be negative (got %d)", c.RequestsPerMinute)
	}
	if c.RequestsPerMinute > 0 && c.Burst <= 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"chat rate limit burst must be positive when requests per minute is set (got burst=%d, rpm=%d)",
			c.Burst, c.RequestsPerMinute)
	}
	if c.Enabled && c.MaxConcurrentStreams <= 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"chat max concurrent streams must be positive when chat rate limiting is enabled (got %d)",
			c.MaxConcurrentStreams)
	}
	if c.MaxKeys < 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"chat rate limit max keys must not be negative (got %d)", c.MaxKeys)
	}
	return nil
}

type chatVisitorEntry struct {
	tokens        float64
	lastSeen      time.Time
	lastRefill    time.Time
	activeStreams int
}

type chatRateLimiter struct {
	cfg      chatRateLimitConfig
	mu       sync.Mutex
	visitors map[string]*chatVisitorEntry
}

func newChatRateLimiter(cfg chatRateLimitConfig, done <-chan struct{}) (*chatRateLimiter, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}

	l := &chatRateLimiter{
		cfg:      cfg,
		visitors: make(map[string]*chatVisitorEntry),
	}
	go l.cleanupLoop(done)
	return l, nil
}

func (l *chatRateLimiter) cleanupLoop(done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			const staleThreshold = 10 * time.Minute

			type entry struct {
				key      string
				lastSeen time.Time
			}
			entries := make([]entry, 0, len(l.visitors))
			for key, v := range l.visitors {
				if v.activeStreams == 0 && now.Sub(v.lastSeen) > staleThreshold {
					delete(l.visitors, key)
				} else {
					entries = append(entries, entry{key: key, lastSeen: v.lastSeen})
				}
			}

			if l.cfg.MaxKeys > 0 && len(entries) > l.cfg.MaxKeys {
				slices.SortFunc(entries, func(a, b entry) int {
					if a.lastSeen.Before(b.lastSeen) {
						return -1
					}
					if a.lastSeen.After(b.lastSeen) {
						return 1
					}
					return 0
				})

				toEvict := len(entries) - l.cfg.MaxKeys
				actualEvicted := 0
				for i := 0; i < toEvict; i++ {
					if v := l.visitors[entries[i].key]; v != nil && v.activeStreams == 0 {
						delete(l.visitors, entries[i].key)
						actualEvicted++
					}
				}
				slog.Warn("chat rate limiter key cap enforced",
					"intended", toEvict, "evicted", actualEvicted, "max_keys", l.cfg.MaxKeys, "remaining", len(l.visitors))
				if actualEvicted < toEvict {
					slog.Warn("chat rate limiter: partial eviction — active streams protected some keys from eviction",
						"intended", toEvict, "evicted", actualEvicted, "protected", toEvict-actualEvicted, "remaining", len(l.visitors))
				}
			}
			l.mu.Unlock()
		case <-done:
			return
		}
	}
}

func (l *chatRateLimiter) allowRequest(key string) bool {
	if l == nil {
		return true
	}
	if l.cfg.RequestsPerMinute <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	v := l.getOrCreateVisitorLocked(key)
	now := time.Now()
	v.lastSeen = now

	// Token bucket refill (rpm -> tokens/sec)
	ratePerSecond := float64(l.cfg.RequestsPerMinute) / 60.0
	elapsed := now.Sub(v.lastRefill).Seconds()
	v.tokens += elapsed * ratePerSecond
	if v.tokens > float64(l.cfg.Burst) {
		v.tokens = float64(l.cfg.Burst)
	}
	v.lastRefill = now

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

func (l *chatRateLimiter) acquireStream(key string) bool {
	if l == nil {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	v := l.getOrCreateVisitorLocked(key)
	v.lastSeen = time.Now()
	if v.activeStreams >= l.cfg.MaxConcurrentStreams {
		return false
	}
	v.activeStreams++
	return true
}

func (l *chatRateLimiter) releaseStream(key string) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	v := l.visitors[key]
	if v == nil {
		return
	}
	if v.activeStreams == 0 {
		slog.Error("chat rate limiter: stream slot underflow — release called with no active streams",
			"key", key,
			"active_streams", v.activeStreams)
		return
	}
	v.activeStreams--
	v.lastSeen = time.Now()
}

func (l *chatRateLimiter) getOrCreateVisitorLocked(key string) *chatVisitorEntry {
	if key == "" {
		key = "ip:unknown"
	}
	if v, ok := l.visitors[key]; ok {
		return v
	}
	now := time.Now()
	v := &chatVisitorEntry{
		tokens:     float64(l.cfg.Burst),
		lastSeen:   now,
		lastRefill: now,
	}
	l.visitors[key] = v
	return v
}

type clientIPContextKey struct{}

func clientIPContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRemoteAddr(r.RemoteAddr)
		ctx := context.WithValue(r.Context(), clientIPContextKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		truncated := remoteAddr
		if len(truncated) > 64 {
			truncated = truncated[:64] + "..."
		}
		slog.Warn("chat rate limiter: failed to parse RemoteAddr, using raw value as key",
			"remote_addr", truncated,
			"error", err)
		return remoteAddr
	}
	return host
}

func clientIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPContextKey{}).(string); ok {
		return ip
	}
	return ""
}

func (s *Server) chatLimiterKey(ctx context.Context) (key string, keyType string) {
	if user := UserFromContext(ctx); user != nil && user.ID() != "" {
		return "user:" + user.ID(), "user"
	}
	ip := clientIPFromContext(ctx)
	if ip == "" {
		return "ip:unknown", "ip"
	}
	return "ip:" + ip, "ip"
}

// hashKey returns the first 8 hex chars of SHA-256(key) for log privacy.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:4]) // 4 bytes = 8 hex chars
}

func (s *Server) checkChatRequestLimit(ctx context.Context, endpoint string) error {
	if s.chatLimiter == nil {
		return nil
	}
	key, keyType := s.chatLimiterKey(ctx)
	if s.chatLimiter.allowRequest(key) {
		return nil
	}
	slog.Warn("chat rate limit exceeded", "reason", "request_rate_exceeded", "endpoint", endpoint, "key_type", keyType, "key_hash", hashKey(key))
	return chatTooManyRequests("chat rate limit exceeded")
}

func (s *Server) acquireChatStreamSlot(ctx context.Context, endpoint string) (string, error) {
	if s.chatLimiter == nil {
		return "", nil
	}
	key, keyType := s.chatLimiterKey(ctx)
	if s.chatLimiter.acquireStream(key) {
		return key, nil
	}
	slog.Warn("chat stream concurrency limit exceeded", "reason", "concurrency_exceeded", "endpoint", endpoint, "key_type", keyType, "key_hash", hashKey(key))
	return "", chatTooManyRequests("too many active chat streams")
}

func (s *Server) releaseChatStreamSlot(key string) {
	if s.chatLimiter == nil {
		return
	}
	s.chatLimiter.releaseStream(key)
}

func chatTooManyRequests(msg string) error {
	err429 := huma.NewError(http.StatusTooManyRequests, msg)
	return huma.ErrorWithHeaders(err429, http.Header{"Retry-After": []string{chatRateLimitRetryAfter}})
}

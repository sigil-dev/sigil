// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig configures per-IP rate limiting.
type RateLimitConfig struct {
	// RequestsPerSecond is the sustained request rate per IP. Zero disables limiting.
	RequestsPerSecond float64
	// Burst is the maximum burst size per IP.
	Burst int
}

// rateLimitMiddleware returns middleware that enforces per-IP rate limits.
// Returns a pass-through middleware when cfg.RequestsPerSecond is zero.
func rateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.RequestsPerSecond <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	var (
		mu       sync.Mutex
		visitors = make(map[string]*visitorEntry)
	)

	// Periodically clean up stale entries to prevent unbounded growth.
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			mu.Lock()
			now := time.Now()
			for ip, v := range visitors {
				if now.Sub(v.lastSeen) > 10*time.Minute {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			mu.Lock()
			v, exists := visitors[ip]
			if !exists {
				v = &visitorEntry{
					tokens:     float64(cfg.Burst),
					lastSeen:   time.Now(),
					lastRefill: time.Now(),
					rate:       cfg.RequestsPerSecond,
					burst:      float64(cfg.Burst),
				}
				visitors[ip] = v
			}
			v.lastSeen = time.Now()

			// Token bucket: refill based on elapsed time
			elapsed := time.Since(v.lastRefill).Seconds()
			v.tokens += elapsed * v.rate
			if v.tokens > v.burst {
				v.tokens = v.burst
			}
			v.lastRefill = time.Now()

			if v.tokens < 1 {
				mu.Unlock()
				slog.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}
			v.tokens--
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

type visitorEntry struct {
	tokens     float64
	lastSeen   time.Time
	lastRefill time.Time
	rate       float64
	burst      float64
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// RateLimitConfig configures per-IP rate limiting.
type RateLimitConfig struct {
	// RequestsPerSecond is the sustained request rate per IP. Zero disables limiting.
	RequestsPerSecond float64
	// Burst is the maximum burst size per IP.
	Burst int
}

// Validate checks that the RateLimitConfig is valid.
func (c RateLimitConfig) Validate() error {
	if c.RequestsPerSecond > 0 && c.Burst <= 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"rate limit burst must be positive when rate is set (got burst=%d, rate=%g)",
			c.Burst, c.RequestsPerSecond)
	}
	if c.RequestsPerSecond < 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"rate limit requests per second must not be negative (got %g)",
			c.RequestsPerSecond)
	}
	return nil
}

// rateLimitMiddleware returns middleware that enforces per-IP rate limits.
// Returns a pass-through middleware when cfg.RequestsPerSecond is zero.
// The done channel signals the cleanup goroutine to exit on shutdown.
func rateLimitMiddleware(cfg RateLimitConfig, done <-chan struct{}) func(http.Handler) http.Handler {
	if cfg.RequestsPerSecond <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	var (
		mu       sync.Mutex
		visitors = make(map[string]*visitorEntry)
	)

	// Periodically clean up stale entries to prevent unbounded growth.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for ip, v := range visitors {
					if now.Sub(v.lastSeen) > 10*time.Minute {
						delete(visitors, ip)
					}
				}
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip port from RemoteAddr to prevent trivial bypass
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// RemoteAddr might not have a port (e.g., in tests)
				host = r.RemoteAddr
			}
			ip := host

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

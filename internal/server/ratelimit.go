// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"log/slog"
	"net"
	"net/http"
	"slices"
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
	// MaxVisitors is the maximum number of unique IPs tracked concurrently.
	// When the visitor map exceeds this size, the oldest entries are evicted during cleanup.
	// Zero means unlimited (not recommended for production). Default: 10000.
	MaxVisitors int
}

// Validate checks that the RateLimitConfig is valid and applies defaults.
func (c *RateLimitConfig) Validate() error {
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
	if c.MaxVisitors < 0 {
		return sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
			"rate limit max visitors must not be negative (got %d)",
			c.MaxVisitors)
	}
	// Apply default MaxVisitors if not set
	if c.MaxVisitors == 0 {
		c.MaxVisitors = 10000
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
				const staleThreshold = 10 * time.Minute

				// Build sorted list of entries while removing stale ones in a single pass.
				type entry struct {
					ip       string
					lastSeen time.Time
				}
				entries := make([]entry, 0, len(visitors))
				for ip, v := range visitors {
					if now.Sub(v.lastSeen) > staleThreshold {
						delete(visitors, ip)
					} else {
						entries = append(entries, entry{ip: ip, lastSeen: v.lastSeen})
					}
				}

				// Enforce MaxVisitors cap by evicting oldest remaining entries if needed.
				if cfg.MaxVisitors > 0 && len(entries) > cfg.MaxVisitors {
					// Sort by lastSeen ascending (oldest first)
					slices.SortFunc(entries, func(a, b entry) int {
						if a.lastSeen.Before(b.lastSeen) {
							return -1
						}
						if a.lastSeen.After(b.lastSeen) {
							return 1
						}
						return 0
					})
					// Evict oldest entries until we're under the cap
					toEvict := len(entries) - cfg.MaxVisitors
					for i := 0; i < toEvict; i++ {
						delete(visitors, entries[i].ip)
					}
					slog.Warn("rate limiter visitor map cap enforced",
						"evicted", toEvict, "max_visitors", cfg.MaxVisitors, "remaining", len(visitors))
				}
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip port from RemoteAddr to rate-limit by IP, not by connection.
			// Without this, clients opening multiple connections from ephemeral ports
			// would each get separate rate limit buckets, bypassing the limit.
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
				if _, err := w.Write([]byte(`{"error":"rate limit exceeded"}`)); err != nil {
					slog.Warn("failed to write rate limit response", "error", err)
				}
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

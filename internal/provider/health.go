// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"sync"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/health"
)

// HealthMetrics is an alias for health.Metrics, preserved for backward
// compatibility with existing callers in this package and its consumers.
type HealthMetrics = health.Metrics

// HealthTracker provides simple health state tracking for providers.
// A provider is considered healthy until RecordFailure is called.
// After a failure, the provider is marked unhealthy for a cooldown
// period, after which it becomes available again to allow recovery.
type HealthTracker struct {
	mu           sync.RWMutex
	healthy      bool
	failedAt     time.Time
	cooldown     time.Duration
	failureCount int64
	nowFunc      func() time.Time // for testing
}

// DefaultHealthCooldown is the duration after which an unhealthy provider
// becomes eligible for retry.
const DefaultHealthCooldown = 30 * time.Second

// NewHealthTracker creates a HealthTracker that starts healthy.
// Returns an error if cooldown is zero or negative.
func NewHealthTracker(cooldown time.Duration) (*HealthTracker, error) {
	if cooldown <= 0 {
		return nil, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"health tracker cooldown must be positive, got %s", cooldown)
	}
	return &HealthTracker{
		healthy:  true,
		cooldown: cooldown,
		nowFunc:  time.Now,
	}, nil
}

// isHealthyLocked reports whether the provider is healthy or the cooldown
// has elapsed. The caller MUST hold at least h.mu.RLock.
func (h *HealthTracker) isHealthyLocked() bool {
	if h.healthy {
		return true
	}
	// Allow retry after cooldown expires.
	return h.nowFunc().Sub(h.failedAt) >= h.cooldown
}

// IsHealthy returns true if the provider is healthy or the cooldown has elapsed.
func (h *HealthTracker) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.isHealthyLocked()
}

// RecordSuccess marks the provider as healthy.
func (h *HealthTracker) RecordSuccess() {
	h.mu.Lock()
	h.healthy = true
	h.mu.Unlock()
}

// RecordFailure marks the provider as unhealthy and increments the
// cumulative failure count.
func (h *HealthTracker) RecordFailure() {
	h.mu.Lock()
	h.healthy = false
	h.failedAt = h.nowFunc()
	h.failureCount++
	h.mu.Unlock()
}

// SetNowFunc overrides the time source (for testing).
func (h *HealthTracker) SetNowFunc(fn func() time.Time) {
	h.mu.Lock()
	h.nowFunc = fn
	h.mu.Unlock()
}

// HealthMetrics returns a point-in-time snapshot of the tracker's health state.
// The returned struct is safe to serialize and does not hold any references to
// internal tracker state.
func (h *HealthTracker) HealthMetrics() HealthMetrics {
	h.mu.RLock()
	defer h.mu.RUnlock()

	m := HealthMetrics{
		FailureCount: h.failureCount,
	}

	if h.failureCount > 0 {
		t := h.failedAt
		m.LastFailureAt = &t
	}

	m.Available = h.isHealthyLocked()
	if !h.healthy {
		// Provider is marked unhealthy — compute cooldown deadline.
		cooldownEnd := h.failedAt.Add(h.cooldown)
		m.CooldownUntil = &cooldownEnd
	}
	return m
}

// HealthMetricsPtr is a convenience wrapper around HealthMetrics that returns
// a pointer, avoiding the need for an intermediate variable at call sites.
func (h *HealthTracker) HealthMetricsPtr() *HealthMetrics {
	hm := h.HealthMetrics()
	return &hm
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"sync"
	"time"
)

// HealthTracker provides simple health state tracking for providers.
// A provider is considered healthy until RecordFailure is called.
// After a failure, the provider is marked unhealthy for a cooldown
// period, after which it becomes available again to allow recovery.
type HealthTracker struct {
	mu       sync.RWMutex
	healthy  bool
	failedAt time.Time
	cooldown time.Duration
	nowFunc  func() time.Time // for testing
}

// DefaultHealthCooldown is the duration after which an unhealthy provider
// becomes eligible for retry.
const DefaultHealthCooldown = 30 * time.Second

// NewHealthTracker creates a HealthTracker that starts healthy.
func NewHealthTracker(cooldown time.Duration) *HealthTracker {
	return &HealthTracker{
		healthy:  true,
		cooldown: cooldown,
		nowFunc:  time.Now,
	}
}

// IsHealthy returns true if the provider is healthy or the cooldown has elapsed.
func (h *HealthTracker) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.healthy {
		return true
	}
	// Allow retry after cooldown expires.
	return h.nowFunc().Sub(h.failedAt) >= h.cooldown
}

// RecordSuccess marks the provider as healthy.
func (h *HealthTracker) RecordSuccess() {
	h.mu.Lock()
	h.healthy = true
	h.mu.Unlock()
}

// RecordFailure marks the provider as unhealthy.
func (h *HealthTracker) RecordFailure() {
	h.mu.Lock()
	h.healthy = false
	h.failedAt = h.nowFunc()
	h.mu.Unlock()
}

// SetNowFunc overrides the time source (for testing).
func (h *HealthTracker) SetNowFunc(fn func() time.Time) {
	h.mu.Lock()
	h.nowFunc = fn
	h.mu.Unlock()
}

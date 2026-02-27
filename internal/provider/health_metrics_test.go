// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"sync"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthTracker_HealthMetrics(t *testing.T) {
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	second := now.Add(5 * time.Second)
	later := now.Add(11 * time.Second)

	cooldownUntilNow := now.Add(10 * time.Second)
	cooldownUntilSecond := second.Add(10 * time.Second)

	tests := []struct {
		name  string
		setup func(h *provider.HealthTracker)
		want  provider.HealthMetrics
	}{
		{
			name:  "zero value initial state",
			setup: func(h *provider.HealthTracker) {},
			want: provider.HealthMetrics{
				Available:     true,
				FailureCount:  0,
				LastFailureAt: nil,
				CooldownUntil: nil,
			},
		},
		{
			name: "single failure",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
			},
			want: provider.HealthMetrics{
				Available:     false,
				FailureCount:  1,
				LastFailureAt: &now,
				CooldownUntil: &cooldownUntilNow,
			},
		},
		{
			name: "multiple failures reflect most recent",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
				h.SetNowFunc(func() time.Time { return second })
				h.RecordFailure()
			},
			want: provider.HealthMetrics{
				Available:     false,
				FailureCount:  2,
				LastFailureAt: &second,
				CooldownUntil: &cooldownUntilSecond,
			},
		},
		{
			name: "cooldown expiry at exact boundary is available",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
				h.SetNowFunc(func() time.Time { return now.Add(10 * time.Second) })
			},
			want: provider.HealthMetrics{
				Available:     true,
				FailureCount:  1,
				LastFailureAt: &now,
				CooldownUntil: nil,
			},
		},
		{
			name: "cooldown expiry makes available again",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
				h.SetNowFunc(func() time.Time { return later })
			},
			want: provider.HealthMetrics{
				Available:     true,
				FailureCount:  1,
				LastFailureAt: &now,
				CooldownUntil: nil,
			},
		},
		{
			name: "recovery after failure clears cooldown",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
				h.RecordSuccess()
			},
			want: provider.HealthMetrics{
				Available:     true,
				FailureCount:  1,
				LastFailureAt: &now,
				CooldownUntil: nil,
			},
		},
		{
			name: "failure count is cumulative and not reset on success",
			setup: func(h *provider.HealthTracker) {
				h.SetNowFunc(func() time.Time { return now })
				h.RecordFailure()
				h.RecordFailure()
				h.RecordFailure()
				h.RecordSuccess()
			},
			want: provider.HealthMetrics{
				Available:     true,
				FailureCount:  3,
				LastFailureAt: &now,
				CooldownUntil: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := provider.NewHealthTracker(10 * time.Second)
			require.NoError(t, err)
			tt.setup(h)
			got := h.HealthMetrics()
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestHealthTracker_HealthMetrics_CooldownUntilUsesTrackerCooldown verifies that
// CooldownUntil is computed as failedAt + h.cooldown, not a hardcoded constant.
// It uses a 30s cooldown (distinct from the 10s default in the table-driven test)
// so that any regression where the snapshot calculation uses a hardcoded value
// would produce an incorrect CooldownUntil and fail the assertion.
func TestHealthTracker_HealthMetrics_CooldownUntilUsesTrackerCooldown(t *testing.T) {
	const cooldown = 30 * time.Second
	failedAt := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	wantCooldownUntil := failedAt.Add(cooldown)

	h, err := provider.NewHealthTracker(cooldown)
	require.NoError(t, err)
	h.SetNowFunc(func() time.Time { return failedAt })
	h.RecordFailure()

	got := h.HealthMetrics()

	require.NotNil(t, got.CooldownUntil, "CooldownUntil must be non-nil after failure")
	assert.Equal(t, wantCooldownUntil, *got.CooldownUntil,
		"CooldownUntil must equal failedAt + cooldown duration")
	assert.Equal(t, &failedAt, got.LastFailureAt)
	assert.False(t, got.Available)
}

func TestHealthTracker_HealthMetrics_ConcurrentAccess(t *testing.T) {
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = h.HealthMetrics()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				h.RecordFailure()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				h.RecordSuccess()
			}
		}()
	}

	wg.Wait()

	// Should not panic or race — verified with -race flag.
	m := h.HealthMetrics()
	// FailureCount cannot exceed total RecordFailure calls.
	assert.LessOrEqual(t, m.FailureCount, int64(goroutines*iterations),
		"FailureCount should not exceed total RecordFailure calls")
	// FailureCount must equal the exact number of RecordFailure calls.
	// RecordSuccess does not reset the counter, and the mutex serialises all
	// writes, so the count must be exact — not merely > 0.
	assert.Equal(t, int64(goroutines*iterations), m.FailureCount,
		"FailureCount must equal total RecordFailure calls")
}

func TestHealthTracker_HealthMetrics_ConcurrentSetNowFunc(t *testing.T) {
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)

	const goroutines = 5
	const iterations = 100

	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = h.HealthMetrics()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				h.SetNowFunc(func() time.Time { return time.Now() })
			}
		}()
	}

	wg.Wait()

	// Should not panic or race — verified with -race flag.
	// This test validates lock ordering between SetNowFunc (write lock)
	// and HealthMetrics (read lock). No failures recorded, so count must be 0.
	m := h.HealthMetrics()
	assert.Equal(t, int64(0), m.FailureCount,
		"FailureCount should be zero when no failures were recorded")
}

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
				CooldownUntil: &cooldownUntilNow,
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
	// Non-deterministic but failure count should be non-negative
	assert.GreaterOrEqual(t, m.FailureCount, int64(0))
}

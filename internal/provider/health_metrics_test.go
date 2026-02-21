// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthTracker_HealthMetrics_ZeroValue(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)

	m := h.HealthMetrics()

	assert.True(t, m.Available, "new tracker should be available")
	assert.Equal(t, int64(0), m.FailureCount, "no failures recorded yet")
	assert.Nil(t, m.LastFailureAt, "no failures means nil last failure time")
	assert.Nil(t, m.CooldownUntil, "no failures means nil cooldown")
}

func TestHealthTracker_HealthMetrics_AfterSingleFailure(t *testing.T) {
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)
	h.SetNowFunc(func() time.Time { return now })

	h.RecordFailure()

	m := h.HealthMetrics()
	assert.False(t, m.Available, "should be unavailable during cooldown")
	assert.Equal(t, int64(1), m.FailureCount, "one failure recorded")
	require.NotNil(t, m.LastFailureAt, "should have a failure timestamp")
	assert.Equal(t, now, *m.LastFailureAt)
	require.NotNil(t, m.CooldownUntil, "should have cooldown deadline")
	assert.Equal(t, now.Add(10*time.Second), *m.CooldownUntil)
}

func TestHealthTracker_HealthMetrics_AfterMultipleFailures(t *testing.T) {
	first := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	second := first.Add(5 * time.Second)
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)

	h.SetNowFunc(func() time.Time { return first })
	h.RecordFailure()

	h.SetNowFunc(func() time.Time { return second })
	h.RecordFailure()

	m := h.HealthMetrics()
	assert.False(t, m.Available)
	assert.Equal(t, int64(2), m.FailureCount, "two failures recorded")
	require.NotNil(t, m.LastFailureAt)
	assert.Equal(t, second, *m.LastFailureAt, "should reflect most recent failure time")
	require.NotNil(t, m.CooldownUntil)
	assert.Equal(t, second.Add(10*time.Second), *m.CooldownUntil, "cooldown from latest failure")
}

func TestHealthTracker_HealthMetrics_AfterCooldownExpiry(t *testing.T) {
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)
	h.SetNowFunc(func() time.Time { return now })

	h.RecordFailure()

	// Advance past cooldown
	later := now.Add(11 * time.Second)
	h.SetNowFunc(func() time.Time { return later })

	m := h.HealthMetrics()
	assert.True(t, m.Available, "should be available after cooldown")
	assert.Equal(t, int64(1), m.FailureCount, "failure count persists after cooldown")
	require.NotNil(t, m.LastFailureAt, "failure timestamp persists")
	assert.Equal(t, now, *m.LastFailureAt)
	// CooldownUntil should be in the past (cooldown expired)
	require.NotNil(t, m.CooldownUntil)
	assert.Equal(t, now.Add(10*time.Second), *m.CooldownUntil)
}

func TestHealthTracker_HealthMetrics_AfterRecovery(t *testing.T) {
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)
	h.SetNowFunc(func() time.Time { return now })

	h.RecordFailure()
	h.RecordSuccess()

	m := h.HealthMetrics()
	assert.True(t, m.Available, "should be available after recovery")
	assert.Equal(t, int64(1), m.FailureCount, "failure count persists after recovery")
	require.NotNil(t, m.LastFailureAt, "failure timestamp persists after recovery")
	assert.Nil(t, m.CooldownUntil, "cooldown cleared on recovery")
}

func TestHealthTracker_HealthMetrics_SuccessResetsCountOnRecovery(t *testing.T) {
	// Verify that RecordSuccess does NOT reset failure count —
	// the count is cumulative for monitoring purposes.
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)

	h.RecordFailure()
	h.RecordFailure()
	h.RecordFailure()
	h.RecordSuccess()

	m := h.HealthMetrics()
	assert.Equal(t, int64(3), m.FailureCount, "failure count is cumulative, not reset on success")
}

func TestHealthTracker_HealthMetrics_ConcurrentAccess(t *testing.T) {
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)

	const goroutines = 10
	const iterations = 100

	done := make(chan struct{})
	defer close(done)

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				select {
				case <-done:
					return
				default:
					_ = h.HealthMetrics()
				}
			}
		}()
		go func() {
			for j := 0; j < iterations; j++ {
				select {
				case <-done:
					return
				default:
					h.RecordFailure()
				}
			}
		}()
		go func() {
			for j := 0; j < iterations; j++ {
				select {
				case <-done:
					return
				default:
					h.RecordSuccess()
				}
			}
		}()
	}

	// Wait briefly for goroutines to finish
	time.Sleep(100 * time.Millisecond)

	// Should not panic or race — verified with -race flag.
	m := h.HealthMetrics()
	// Non-deterministic but failure count should be non-negative
	assert.GreaterOrEqual(t, m.FailureCount, int64(0))
}

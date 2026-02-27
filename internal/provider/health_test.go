// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/provider"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthTracker_InvalidCooldown(t *testing.T) {
	tests := []struct {
		name     string
		cooldown time.Duration
	}{
		{
			name:     "zero cooldown",
			cooldown: 0,
		},
		{
			name:     "negative cooldown",
			cooldown: -1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := provider.NewHealthTracker(tt.cooldown)
			require.Error(t, err)
			assert.Nil(t, h)
			assert.Contains(t, err.Error(), "health tracker cooldown must be positive")
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue),
				"invalid cooldown should carry CodeConfigValidateInvalidValue")
		})
	}
}

func TestHealthTracker_StartsHealthy(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)
	assert.True(t, h.IsHealthy())
}

func TestHealthTracker_FailureMakesUnhealthy(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)
	h.RecordFailure()
	assert.False(t, h.IsHealthy())
}

func TestHealthTracker_SuccessRestoresHealth(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)
	h.RecordFailure()
	assert.False(t, h.IsHealthy())

	h.RecordSuccess()
	assert.True(t, h.IsHealthy())
}

func TestHealthTracker_CooldownExpiry(t *testing.T) {
	now := time.Now()
	h, err := provider.NewHealthTracker(10 * time.Second)
	require.NoError(t, err)
	h.SetNowFunc(func() time.Time { return now })

	h.RecordFailure()
	assert.False(t, h.IsHealthy())

	// Advance time past cooldown.
	h.SetNowFunc(func() time.Time { return now.Add(11 * time.Second) })
	assert.True(t, h.IsHealthy(), "should recover after cooldown")
}

func TestHealthTracker_CooldownBoundary(t *testing.T) {
	cooldown := 10 * time.Second
	now := time.Now()

	tests := []struct {
		name        string
		elapsed     time.Duration
		wantHealthy bool
	}{
		{
			name:        "before cooldown",
			elapsed:     9 * time.Second,
			wantHealthy: false,
		},
		{
			name:        "at exact cooldown boundary",
			elapsed:     10 * time.Second,
			wantHealthy: true,
		},
		{
			name:        "after cooldown",
			elapsed:     11 * time.Second,
			wantHealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := provider.NewHealthTracker(cooldown)
			require.NoError(t, err)
			h.SetNowFunc(func() time.Time { return now })

			h.RecordFailure()
			assert.False(t, h.IsHealthy(), "should be unhealthy immediately after failure")

			// Advance time by elapsed duration.
			h.SetNowFunc(func() time.Time { return now.Add(tt.elapsed) })

			got := h.IsHealthy()
			assert.Equal(t, tt.wantHealthy, got)
		})
	}
}

func TestHealthTracker_MidStreamFailure(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)

	// Simulate successful start of streaming
	h.RecordSuccess()
	assert.True(t, h.IsHealthy(), "should be healthy after initial success")

	// Simulate mid-stream failure (abnormal termination after first event)
	h.RecordFailure()
	assert.False(t, h.IsHealthy(), "should be unhealthy after mid-stream failure despite prior success")
}

// TestHealthTracker_ConcurrentRecordCalls tests provider health tracking race condition.
// RecordFailure() can be called from both agent loop (pre-stream) AND provider
// internals (mid-stream) concurrently. This test verifies concurrent calls
// don't corrupt state. Run with `go test -race` to detect data races.
func TestHealthTracker_ConcurrentRecordCalls(t *testing.T) {
	h, err := provider.NewHealthTracker(30 * time.Second)
	require.NoError(t, err)

	const goroutines = 10
	const iterations = 100

	done := make(chan struct{})
	defer close(done)

	// Launch multiple goroutines calling RecordFailure and RecordSuccess concurrently.
	for i := 0; i < goroutines; i++ {
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
		go func() {
			for j := 0; j < iterations; j++ {
				select {
				case <-done:
					return
				default:
					_ = h.IsHealthy()
				}
			}
		}()
	}

	// Wait a bit for goroutines to finish their work.
	time.Sleep(100 * time.Millisecond)

	// Test passes if no data race is detected by `-race` flag.
	// Final state is non-deterministic due to concurrency but should be valid.
	// Either healthy or unhealthy with a valid failedAt timestamp.
	_ = h.IsHealthy()
}

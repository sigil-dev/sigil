// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestHealthTracker_StartsHealthy(t *testing.T) {
	h := provider.NewHealthTracker(30 * time.Second)
	assert.True(t, h.IsHealthy())
}

func TestHealthTracker_FailureMakesUnhealthy(t *testing.T) {
	h := provider.NewHealthTracker(30 * time.Second)
	h.RecordFailure()
	assert.False(t, h.IsHealthy())
}

func TestHealthTracker_SuccessRestoresHealth(t *testing.T) {
	h := provider.NewHealthTracker(30 * time.Second)
	h.RecordFailure()
	assert.False(t, h.IsHealthy())

	h.RecordSuccess()
	assert.True(t, h.IsHealthy())
}

func TestHealthTracker_CooldownExpiry(t *testing.T) {
	now := time.Now()
	h := provider.NewHealthTracker(10 * time.Second)
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
		name     string
		elapsed  time.Duration
		wantHealthy bool
	}{
		{
			name:     "before cooldown",
			elapsed:  9 * time.Second,
			wantHealthy: false,
		},
		{
			name:     "at exact cooldown boundary",
			elapsed:  10 * time.Second,
			wantHealthy: true,
		},
		{
			name:     "after cooldown",
			elapsed:  11 * time.Second,
			wantHealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := provider.NewHealthTracker(cooldown)
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

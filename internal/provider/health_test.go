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

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package health

import "time"

// Metrics exposes the current health state of a provider for monitoring
// and operator visibility. All fields are point-in-time snapshots safe
// to serialize to JSON.
type Metrics struct {
	FailureCount  int64      `json:"failure_count"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	Available     bool       `json:"available"`
}

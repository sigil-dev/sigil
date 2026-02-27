// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package health

import "time"

// Metrics exposes the current health state of a provider for monitoring
// and operator visibility. All fields are point-in-time snapshots safe
// to serialize to JSON.
type Metrics struct {
	FailureCount  int64      `json:"failure_count" doc:"Cumulative count of failures since tracker creation"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty" doc:"Timestamp of the most recent failure; omitted if no failures recorded"`
	CooldownUntil *time.Time `json:"cooldown_until,omitempty" doc:"Time until which the provider is in cooldown; omitted when available"`
	Available     bool       `json:"available" doc:"Whether the provider is currently available for requests"`
}

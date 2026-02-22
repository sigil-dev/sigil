// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package container export_test.go exposes internal fields for black-box tests.
package container

import "time"

// StopTimeouts returns a snapshot of the runtime's internal stopTimeouts map.
// It is exported only for tests (export_test.go is not compiled into production builds).
func (r *Runtime) StopTimeouts() map[string]time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := make(map[string]time.Duration, len(r.stopTimeouts))
	for k, v := range r.stopTimeouts {
		snapshot[k] = v
	}
	return snapshot
}

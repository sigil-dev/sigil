// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"slices"
	"time"
)

// ContextWithUser injects an AuthenticatedUser into a context for testing.
// This is exported only to _test packages via the export_test.go convention.
func ContextWithUser(ctx context.Context, user *AuthenticatedUser) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

// CheckWorkspaceMembership exposes checkWorkspaceMembership for direct unit testing.
func (s *Server) CheckWorkspaceMembership(ctx context.Context, workspaceID string) error {
	return s.checkWorkspaceMembership(ctx, workspaceID)
}

// RequireAdmin exposes requireAdmin for direct unit testing.
func (s *Server) RequireAdmin(ctx context.Context, permission, op string) error {
	return s.requireAdmin(ctx, permission, op)
}

// RunCleanupNow synchronously executes the cleanup body of cleanupLoop once.
// It is provided for testing only, so tests do not have to wait for the 5-minute ticker.
func (l *chatRateLimiter) RunCleanupNow() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	const staleThreshold = 10 * time.Minute

	type entry struct {
		key      string
		lastSeen time.Time
	}
	entries := make([]entry, 0, len(l.visitors))
	for key, v := range l.visitors {
		if v.activeStreams == 0 && now.Sub(v.lastSeen) > staleThreshold {
			delete(l.visitors, key)
		} else {
			entries = append(entries, entry{key: key, lastSeen: v.lastSeen})
		}
	}

	if l.cfg.MaxKeys > 0 && len(entries) > l.cfg.MaxKeys {
		slices.SortFunc(entries, func(a, b entry) int {
			if a.lastSeen.Before(b.lastSeen) {
				return -1
			}
			if a.lastSeen.After(b.lastSeen) {
				return 1
			}
			return 0
		})

		toEvict := len(entries) - l.cfg.MaxKeys
		for i := 0; i < toEvict; i++ {
			if v := l.visitors[entries[i].key]; v != nil && v.activeStreams == 0 {
				delete(l.visitors, entries[i].key)
			}
		}
	}
}

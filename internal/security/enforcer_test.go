// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAuditStore struct {
	mu      sync.Mutex
	entries []*store.AuditEntry
	err     error
}

func (m *mockAuditStore) Append(_ context.Context, entry *store.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}

	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditStore) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*store.AuditEntry(nil), m.entries...), nil
}

func (m *mockAuditStore) snapshot() []*store.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*store.AuditEntry(nil), m.entries...)
}

// captureHandler is a slog.Handler that captures all log records for test assertions.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

func TestEnforcer_AllowMatchingCapability(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read", "messages.send.*",
	), security.NewCapabilitySet(
		"exec.*",
	))

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.NoError(t, err)
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "capability_check", entries[0].Action)
	assert.Equal(t, "telegram", entries[0].Plugin)
	assert.Equal(t, "ws-1", entries[0].WorkspaceID)
	assert.Equal(t, "allowed", entries[0].Result)
}

func TestEnforcer_DenyMissingCapability(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	assert.Contains(t, err.Error(), "denied")
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "plugin_allow_missing", entries[0].Details["reason"])
}

func TestEnforcer_DenyExplicitlyDenied(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("malicious", security.NewCapabilitySet(
		"exec.*",
	), security.NewCapabilitySet(
		"exec.*",
	))

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "malicious",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("exec.*"),
		UserPermissions: security.NewCapabilitySet("exec.*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "plugin_deny_match", entries[0].Details["reason"])
}

func TestEnforcer_DenyByWorkspaceScope(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("exec-tool", security.NewCapabilitySet(
		"exec.run.sandboxed",
	), security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "exec-tool",
		Capability:      "exec.run.sandboxed",
		WorkspaceID:     "family",
		WorkspaceAllow:  security.NewCapabilitySet("calendar.*", "shopping.*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "workspace_allow_missing", entries[0].Details["reason"])
}

func TestEnforcer_DenyByUserPermissions(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("exec-tool", security.NewCapabilitySet(
		"exec.run.sandboxed",
	), security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "exec-tool",
		Capability:      "exec.run.sandboxed",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("sessions.*", "messages.*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "user_permission_missing", entries[0].Details["reason"])
}

func TestEnforcer_UnregisteredPlugin(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "unknown",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "plugin_not_registered", entries[0].Details["reason"])
}

func TestEnforcer_UnregisterPlugin(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("temp", security.NewCapabilitySet("sessions.read"), security.NewCapabilitySet())
	enforcer.UnregisterPlugin("temp")

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "temp",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))
	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.NotEmpty(t, entries[0].ID)
	assert.Equal(t, "plugin_not_registered", entries[0].Details["reason"])
}

func TestEnforcer_AuditEntryIDsAreUnique(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	ctx := context.Background()
	require.NoError(t, enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}))
	require.NoError(t, enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}))

	entries := audit.snapshot()
	require.Len(t, entries, 2)
	assert.NotEmpty(t, entries[0].ID)
	assert.NotEmpty(t, entries[1].ID)
	assert.NotEqual(t, entries[0].ID, entries[1].ID)
}

func TestEnforcer_AuditFailure_DeniedStillDenies(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("test-plugin", security.NewCapabilitySet("read"), security.NewCapabilitySet())

	// A denied check should still return the capability denied error, not an audit error.
	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "write", // not in allow set
		WorkspaceAllow:  security.NewCapabilitySet("write"),
		UserPermissions: security.NewCapabilitySet("write"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied),
		"denied check should return capability denied error, not audit error")
	assert.Empty(t, audit.snapshot())
}

func TestEnforcer_AuditFailure_BestEffort(t *testing.T) {
	t.Parallel()

	// sigil-kqd.207: Test that audit store failures don't block operations.
	// This is critical for availability — a failing audit system must not
	// cause cascading failures in the authorization system.
	tests := []struct {
		name           string
		auditErr       error
		pluginAllow    []string
		pluginDeny     []string
		capability     string
		workspaceAllow []string
		userPerms      []string
		expectAllowed  bool
		expectReason   string
	}{
		{
			name:           "allowed check succeeds despite audit failure",
			auditErr:       errors.New("database offline"),
			pluginAllow:    []string{"read"},
			pluginDeny:     []string{},
			capability:     "read",
			workspaceAllow: []string{"read"},
			userPerms:      []string{"read"},
			expectAllowed:  true,
		},
		{
			name:           "denied check still denies despite audit failure",
			auditErr:       errors.New("audit store timeout"),
			pluginAllow:    []string{"read"},
			pluginDeny:     []string{},
			capability:     "write",
			workspaceAllow: []string{"write"},
			userPerms:      []string{"write"},
			expectAllowed:  false,
			expectReason:   "plugin_allow_missing",
		},
		{
			name:           "explicit deny still enforced despite audit failure",
			auditErr:       errors.New("audit store unreachable"),
			pluginAllow:    []string{"exec.*"},
			pluginDeny:     []string{"exec.*"},
			capability:     "exec.run",
			workspaceAllow: []string{"exec.*"},
			userPerms:      []string{"exec.*"},
			expectAllowed:  false,
			expectReason:   "plugin_deny_match",
		},
		{
			name:           "workspace deny still enforced despite audit failure",
			auditErr:       errors.New("audit disk full"),
			pluginAllow:    []string{"file.read"},
			pluginDeny:     []string{},
			capability:     "file.read",
			workspaceAllow: []string{"calendar.*"},
			userPerms:      []string{"*"},
			expectAllowed:  false,
			expectReason:   "workspace_allow_missing",
		},
		{
			name:           "user permission deny still enforced despite audit failure",
			auditErr:       errors.New("audit connection refused"),
			pluginAllow:    []string{"messages.send"},
			pluginDeny:     []string{},
			capability:     "messages.send",
			workspaceAllow: []string{"*"},
			userPerms:      []string{"messages.read"},
			expectAllowed:  false,
			expectReason:   "user_permission_missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &mockAuditStore{err: tt.auditErr}
			enforcer := security.NewEnforcer(audit)
			enforcer.RegisterPlugin("test-plugin",
				security.NewCapabilitySet(tt.pluginAllow...),
				security.NewCapabilitySet(tt.pluginDeny...))

			err := enforcer.Check(context.Background(), security.CheckRequest{
				Plugin:          "test-plugin",
				Capability:      tt.capability,
				WorkspaceID:     "ws-1",
				WorkspaceAllow:  security.NewCapabilitySet(tt.workspaceAllow...),
				UserPermissions: security.NewCapabilitySet(tt.userPerms...),
			})

			if tt.expectAllowed {
				assert.NoError(t, err, "operation should succeed despite audit store failure")
			} else {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied),
					"should return capability denied error, not audit error")
				if tt.expectReason != "" {
					assert.Contains(t, err.Error(), tt.expectReason)
				}
			}

			// Verify audit store received no entries (because append failed).
			assert.Empty(t, audit.snapshot(),
				"audit store should have no entries when append fails")

			// Note: This test verifies best-effort audit behavior where:
			// 1. Operations proceed despite audit failures (allowed checks succeed)
			// 2. Denied checks still return denial errors (not audit errors)
			// 3. Errors are not leaked to clients
			// 4. Warning logs are emitted (verified by code inspection in enforcer.go:116-120, 145-149)
			//    Log capture is not performed as it's not part of the codebase's test patterns.
		})
	}
}

// --- sigil-anm.11: Missing spec test cases ---

func TestEnforcer_AllowThreeWayIntersection(t *testing.T) {
	t.Parallel()

	// Validates that enforcement correctly computes the intersection of:
	// plugin capabilities, workspace allow, and user permissions.
	// Capability "sessions.read" must be in ALL three sets to be allowed.
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("multi-cap", security.NewCapabilitySet(
		"sessions.read", "messages.send", "exec.run",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// All three overlap on sessions.read → allowed
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "multi-cap",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("sessions.*", "messages.*"),
		UserPermissions: security.NewCapabilitySet("sessions.read", "files.read"),
	})
	require.NoError(t, err)

	// messages.send is in plugin + workspace but NOT in user perms → denied
	err = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "multi-cap",
		Capability:      "messages.send",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("sessions.*", "messages.*"),
		UserPermissions: security.NewCapabilitySet("sessions.read", "files.read"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))

	// exec.run is in plugin but NOT in workspace → denied
	err = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "multi-cap",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("sessions.*", "messages.*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))

	// Verify all 3 decisions were audited
	entries := audit.snapshot()
	require.Len(t, entries, 3)
	assert.Equal(t, "allowed", entries[0].Result)
	assert.Equal(t, "denied", entries[1].Result)
	assert.Equal(t, "denied", entries[2].Result)
}

func TestEnforcer_UserWithNoPermissions(t *testing.T) {
	t.Parallel()

	// Security-critical: empty permission set must deny ALL operations (fail-closed).
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet(), // empty = no permissions
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied))

	entries := audit.snapshot()
	require.Len(t, entries, 1)
	assert.Equal(t, "denied", entries[0].Result)
	assert.Equal(t, "user_permission_missing", entries[0].Details["reason"])
}

func TestEnforcer_AuditLogging(t *testing.T) {
	t.Parallel()

	// Verifies that enforcement decisions are audit-logged with correct fields.
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// Allowed check
	require.NoError(t, enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-audit",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}))

	// Denied check
	_ = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "exec.run",
		WorkspaceID:     "ws-audit",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})

	entries := audit.snapshot()
	require.Len(t, entries, 2)

	// Verify allowed entry structure
	allowed := entries[0]
	assert.Equal(t, "capability_check", allowed.Action)
	assert.Equal(t, "telegram", allowed.Actor)
	assert.Equal(t, "telegram", allowed.Plugin)
	assert.Equal(t, "ws-audit", allowed.WorkspaceID)
	assert.Equal(t, "allowed", allowed.Result)
	assert.NotEmpty(t, allowed.ID)
	assert.False(t, allowed.Timestamp.IsZero())
	assert.Equal(t, "sessions.read", allowed.Details["capability"])
	assert.Equal(t, true, allowed.Details["plugin_allow"])
	assert.Equal(t, false, allowed.Details["plugin_deny"])
	assert.Equal(t, true, allowed.Details["workspace_allow"])
	assert.Equal(t, true, allowed.Details["user_allow"])

	// Verify denied entry structure
	denied := entries[1]
	assert.Equal(t, "denied", denied.Result)
	assert.Equal(t, "plugin_allow_missing", denied.Details["reason"])
	assert.NotEmpty(t, denied.ID)
	assert.NotEqual(t, allowed.ID, denied.ID)
}

// --- sigil-anm.17: Nil audit store guard and counter isolation ---

func TestEnforcer_NilAuditStore(t *testing.T) {
	t.Parallel()

	// Nil audit store should be allowed (silent audit disabling).
	// Verify no panic and no audit operations.
	enforcer := security.NewEnforcer(nil)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	// Should succeed even with nil audit store
	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.NoError(t, err)
}

func TestEnforcer_IndependentAuditIDSequences(t *testing.T) {
	t.Parallel()

	// Two independent enforcers should have independent audit ID counters.
	// This ensures multi-tenant scenarios don't have ID collisions.
	audit1 := &mockAuditStore{}
	audit2 := &mockAuditStore{}
	enforcer1 := security.NewEnforcer(audit1)
	enforcer2 := security.NewEnforcer(audit2)

	enforcer1.RegisterPlugin("plugin1", security.NewCapabilitySet("sessions.read"), security.NewCapabilitySet())
	enforcer2.RegisterPlugin("plugin2", security.NewCapabilitySet("sessions.read"), security.NewCapabilitySet())

	ctx := context.Background()

	// Generate multiple audit entries in each enforcer
	for i := 0; i < 3; i++ {
		require.NoError(t, enforcer1.Check(ctx, security.CheckRequest{
			Plugin:          "plugin1",
			Capability:      "sessions.read",
			WorkspaceID:     "ws-1",
			WorkspaceAllow:  security.NewCapabilitySet("*"),
			UserPermissions: security.NewCapabilitySet("*"),
		}))

		require.NoError(t, enforcer2.Check(ctx, security.CheckRequest{
			Plugin:          "plugin2",
			Capability:      "sessions.read",
			WorkspaceID:     "ws-2",
			WorkspaceAllow:  security.NewCapabilitySet("*"),
			UserPermissions: security.NewCapabilitySet("*"),
		}))
	}

	entries1 := audit1.snapshot()
	entries2 := audit2.snapshot()

	require.Len(t, entries1, 3)
	require.Len(t, entries2, 3)

	// Extract all IDs
	ids := make(map[string]bool)
	for _, e := range entries1 {
		assert.NotEmpty(t, e.ID)
		ids[e.ID] = true
	}
	for _, e := range entries2 {
		assert.NotEmpty(t, e.ID)
		ids[e.ID] = true
	}

	// All IDs should be unique (no collision across enforcers)
	assert.Len(t, ids, 6, "expected 6 unique audit IDs across two independent enforcers")
}

// --- Audit fail-closed and threshold escalation tests ---

func TestEnforcer_AuditFailClosed_BlocksAllowPath(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit, security.WithAuditFailClosed(true))
	enforcer.RegisterPlugin("test-plugin",
		security.NewCapabilitySet("read"),
		security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err, "fail-closed mode: audit failure on allow path must return error")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecurityAuditFailure),
		"expected CodeSecurityAuditFailure, got: %v", sigilerr.CodeOf(err))
}

func TestEnforcer_AuditFailClosed_DenyStillDenies(t *testing.T) {
	t.Parallel()

	// Even with fail-closed enabled, a deny decision should return CodePluginCapabilityDenied
	// (not the audit error). The deny path always returns deniedErr regardless of fail-closed.
	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit, security.WithAuditFailClosed(true))
	enforcer.RegisterPlugin("test-plugin",
		security.NewCapabilitySet("read"),
		security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "write", // not in allow set
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginCapabilityDenied),
		"deny path must return capability denied error even in fail-closed mode, got: %v", sigilerr.CodeOf(err))
}

func TestEnforcer_AuditFailClosed_Disabled_AllowsThrough(t *testing.T) {
	t.Parallel()

	// Default (fail-closed=false): audit failure on allow path does not block.
	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit) // no WithAuditFailClosed option = default false
	enforcer.RegisterPlugin("test-plugin",
		security.NewCapabilitySet("read"),
		security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.NoError(t, err, "best-effort mode: audit failure must not block allowed operations")
}

func TestEnforcer_AuditThreshold_Escalation(t *testing.T) {
	// NOTE: Not parallel — this test mutates the global slog default logger to
	// capture log records. Running in parallel would cause other tests' log
	// output to appear in this handler and vice versa.

	// After N consecutive failures, the consecutive counter should reflect that
	// and log level must escalate from Warn to Error at the threshold.
	// We test via the AuditFailCount() accessor AND by capturing slog output.
	handler := &captureHandler{}
	orig := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(orig) })

	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("test-plugin",
		security.NewCapabilitySet("read"),
		security.NewCapabilitySet())

	ctx := context.Background()
	req := security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}

	assert.Equal(t, int64(0), enforcer.AuditAllowFailCount(), "initial count should be 0")

	// 1st failure: counter = 1, below threshold → Warn
	require.NoError(t, enforcer.Check(ctx, req))
	assert.Equal(t, int64(1), enforcer.AuditAllowFailCount())

	// 2nd failure: counter = 2, below threshold → Warn
	require.NoError(t, enforcer.Check(ctx, req))
	assert.Equal(t, int64(2), enforcer.AuditAllowFailCount())

	// 3rd failure: counter = 3 == AuditLogEscalationThreshold → Error
	require.NoError(t, enforcer.Check(ctx, req))
	assert.Equal(t, int64(3), enforcer.AuditAllowFailCount(), "at threshold, count should be 3")

	// Verify log levels: first two must be Warn, third must be Error.
	// Filter to only the audit-failure records emitted by enforcer.Check (not
	// the nil-store warning from NewEnforcer, which uses a different message).
	records := handler.snapshot()
	var auditFailRecords []slog.Record
	for _, r := range records {
		if r.Message == "audit log failure on allowed decision (best-effort, not blocking)" ||
			r.Message == "audit log failure on allowed decision (persistent)" {
			auditFailRecords = append(auditFailRecords, r)
		}
	}
	require.Len(t, auditFailRecords, 3, "expected 3 audit-failure log records")
	assert.Equal(t, slog.LevelWarn, auditFailRecords[0].Level, "1st failure must log at Warn")
	assert.Equal(t, slog.LevelWarn, auditFailRecords[1].Level, "2nd failure must log at Warn")
	assert.Equal(t, slog.LevelError, auditFailRecords[2].Level, "3rd failure (at threshold) must log at Error")
}

func TestEnforcer_AuditThreshold_ResetsOnSuccess(t *testing.T) {
	t.Parallel()

	// After some failures, a successful audit write resets the counter to 0.
	audit := &mockAuditStore{err: errors.New("database offline")}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("test-plugin",
		security.NewCapabilitySet("read"),
		security.NewCapabilitySet())

	ctx := context.Background()
	req := security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	}

	// Accumulate some failures.
	require.NoError(t, enforcer.Check(ctx, req))
	require.NoError(t, enforcer.Check(ctx, req))
	assert.Equal(t, int64(2), enforcer.AuditAllowFailCount())

	// Clear the error — next check will succeed and reset the counter.
	audit.mu.Lock()
	audit.err = nil
	audit.mu.Unlock()

	require.NoError(t, enforcer.Check(ctx, req))
	assert.Equal(t, int64(0), enforcer.AuditAllowFailCount(), "counter must reset to 0 after successful audit write")
}

func TestCheckRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     security.CheckRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: "tool:exec"},
			wantErr: false,
		},
		{
			name:    "empty plugin",
			req:     security.CheckRequest{Plugin: "", Capability: "tool:exec"},
			wantErr: true,
		},
		{
			name:    "empty capability",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: ""},
			wantErr: true,
		},
		{
			name:    "both empty",
			req:     security.CheckRequest{Plugin: "", Capability: ""},
			wantErr: true,
		},
		{
			name:    "valid glob pattern with wildcard",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: "sessions.*"},
			wantErr: false,
		},
		{
			name:    "valid glob pattern with question mark",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: "exec.?un"},
			wantErr: false,
		},
		{
			name:    "invalid glob pattern with unclosed bracket",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: "exec.[run"},
			wantErr: true,
		},
		{
			name:    "invalid glob pattern with unmatched bracket",
			req:     security.CheckRequest{Plugin: "test-plugin", Capability: "tool:[abc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecurityInvalidInput),
					"expected CodeSecurityInvalidInput, got: %v", sigilerr.CodeOf(err))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

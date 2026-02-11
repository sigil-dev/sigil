// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security_test

import (
	"context"
	"errors"
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

func TestEnforcer_DenyWhenAuditAppendFailsReturnsCapabilityDenied(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{err: errors.New("audit backend unavailable")}
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
	assert.Empty(t, audit.snapshot())
}

func TestEnforcer_AllowWhenAuditAppendFailsReturnsStoreFailure(t *testing.T) {
	t.Parallel()

	audit := &mockAuditStore{err: errors.New("audit backend unavailable")}
	enforcer := security.NewEnforcer(audit)
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	err := enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeStoreDatabaseFailure))
	assert.Empty(t, audit.snapshot())
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

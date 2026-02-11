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

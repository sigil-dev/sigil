// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_DiscoverPlugins(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))

	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 1)
	assert.Equal(t, "test-tool", plugins[0].Name)
}

func TestManager_DiscoverSkipsInvalidManifest(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "bad-plugin")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte("invalid: [yaml"), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 0)
}

func TestManager_RegisterCapabilities(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))
	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
  - exec.run.sandboxed
deny_capabilities:
  - config.write.global
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	_, err := mgr.Discover(context.Background())
	require.NoError(t, err)

	err = enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-tool",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.NoError(t, err)
}

type mockAuditStore struct {
	entries []*store.AuditEntry
}

func (m *mockAuditStore) Append(_ context.Context, entry *store.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditStore) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return m.entries, nil
}

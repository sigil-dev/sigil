// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"bytes"
	"context"
	"log/slog"
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
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))

	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0o644))

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
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte("invalid: [yaml"), 0o644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 0)
}

func TestManager_DiscoverLogsInvalidManifestSkip(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "bad-plugin")
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte("not: valid: yaml: ["), 0o644))

	// Capture slog output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	orig := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 0)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "skipping plugin")
	assert.Contains(t, logOutput, "invalid manifest")
	assert.Contains(t, logOutput, "bad-plugin")
}

func TestManager_DiscoverLogsReadFileError(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "unreadable-plugin")
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
	manifestPath := filepath.Join(pluginDir, "plugin.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte("name: test"), 0o644))
	require.NoError(t, os.Chmod(manifestPath, 0o000))

	// Capture slog output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	orig := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 0)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "skipping plugin")
	assert.Contains(t, logOutput, "cannot read manifest")
	assert.Contains(t, logOutput, "unreadable-plugin")
}

func TestManager_RegisterCapabilities(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
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
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0o644))

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

func TestManager_GetKnownPlugin(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))

	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0o644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	_, err := mgr.Discover(context.Background())
	require.NoError(t, err)

	inst, err := mgr.Get("test-tool")
	require.NoError(t, err)
	assert.NotNil(t, inst)
	assert.Equal(t, "test-tool", inst.Name())
	assert.Equal(t, plugin.StateDiscovered, inst.State())
}

func TestManager_GetUnknownPlugin(t *testing.T) {
	dir := t.TempDir()

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	inst, err := mgr.Get("nonexistent-plugin")
	assert.Error(t, err)
	assert.Nil(t, inst)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_ListAfterDiscovery(t *testing.T) {
	dir := t.TempDir()

	pluginNames := []string{"alpha-tool", "charlie-tool", "bravo-tool"}

	for _, name := range pluginNames {
		pluginDir := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(pluginDir, 0o755))

		manifest := `
name: ` + name + `
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
		require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0o644))
	}

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	_, err := mgr.Discover(context.Background())
	require.NoError(t, err)

	list := mgr.List()
	assert.Len(t, list, 3)

	// Verify sorted order by plugin name
	assert.Equal(t, "alpha-tool", list[0].Name())
	assert.Equal(t, "bravo-tool", list[1].Name())
	assert.Equal(t, "charlie-tool", list[2].Name())

	// Verify all are discovered state
	for _, inst := range list {
		assert.Equal(t, plugin.StateDiscovered, inst.State())
	}
}

func TestManager_DiscoverDuplicateNames(t *testing.T) {
	dir := t.TempDir()

	// Create two plugins in different directories but with the same manifest name
	pluginDir1 := filepath.Join(dir, "first-dir")
	require.NoError(t, os.MkdirAll(pluginDir1, 0o755))

	manifest1 := `
name: duplicate-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir1, "plugin.yaml"), []byte(manifest1), 0o644))

	pluginDir2 := filepath.Join(dir, "second-dir")
	require.NoError(t, os.MkdirAll(pluginDir2, 0o755))

	manifest2 := `
name: duplicate-tool
version: 2.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.write
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir2, "plugin.yaml"), []byte(manifest2), 0o644))

	// Capture slog output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	orig := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)

	// Last-wins behavior: only one plugin with the duplicate name
	assert.Len(t, plugins, 2) // Both manifests returned from Discover
	list := mgr.List()
	assert.Len(t, list, 1) // But only one Instance in manager
	assert.Equal(t, "duplicate-tool", list[0].Name())

	// Verify warning was logged
	logOutput := buf.String()
	assert.Contains(t, logOutput, "duplicate plugin name")
	assert.Contains(t, logOutput, "duplicate-tool")
	assert.Contains(t, logOutput, "first-dir")
	assert.Contains(t, logOutput, "second-dir")
}

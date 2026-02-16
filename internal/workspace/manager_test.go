// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package workspace_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigil-dev/sigil/internal/store"
	_ "github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/sigil-dev/sigil/internal/workspace"
)

// newTestManager creates a Manager backed by real SQLite stores in a temp directory.
func newTestManager(t *testing.T) *workspace.Manager {
	t.Helper()
	dataDir := t.TempDir()
	storeCfg := &store.StorageConfig{Backend: "sqlite"}
	m := workspace.NewManager(dataDir, storeCfg)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func assertToolAllowed(t *testing.T, ws *workspace.Workspace, capability string, want bool, msg string) {
	t.Helper()
	got, err := ws.ToolAllowed(capability)
	require.NoError(t, err)
	assert.Equal(t, want, got, msg)
}

func TestManager_OpenWorkspace(t *testing.T) {
	m := newTestManager(t)

	ws, err := m.Open(context.Background(), "test-ws")
	require.NoError(t, err)
	require.NotNil(t, ws)

	assert.Equal(t, "test-ws", ws.ID)
	assert.NotNil(t, ws.SessionStore)
	assert.NotNil(t, ws.MemoryStore)
	assert.NotNil(t, ws.VectorStore)

	// Opening the same workspace again returns the cached instance.
	ws2, err := m.Open(context.Background(), "test-ws")
	require.NoError(t, err)
	assert.Same(t, ws, ws2)
}

func TestManager_RouteMessage(t *testing.T) {
	m := newTestManager(t)

	cfg := workspace.Config{
		"work": {
			Members: []string{"alice", "bob"},
			Bindings: []workspace.Binding{
				{Channel: "slack", ChannelID: "C001"},
			},
		},
	}
	require.NoError(t, m.SetConfig(cfg))

	// Route a message from a bound channel.
	ws, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "slack",
		ChannelID:   "C001",
		UserID:      "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "work", ws.ID)

	// Unbound channel falls back to user-scoped personal workspace.
	ws2, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "T999",
		UserID:      "charlie",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal:charlie", ws2.ID)
}

func TestManager_MembershipCheck(t *testing.T) {
	m := newTestManager(t)

	cfg := workspace.Config{
		"private": {
			Members: []string{"alice"},
			Bindings: []workspace.Binding{
				{Channel: "slack", ChannelID: "C001"},
			},
		},
	}
	require.NoError(t, m.SetConfig(cfg))

	// Non-member should be denied.
	_, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "slack",
		ChannelID:   "C001",
		UserID:      "bob",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a member")
}

func TestManager_ToolAllowlist(t *testing.T) {
	m := newTestManager(t)

	cfg := workspace.Config{
		"tooled": {
			Members: []string{"alice"},
			Tools: workspace.ToolConfig{
				Allow: []string{"calendar.*", "shopping.*"},
				Deny:  []string{"exec.*"},
			},
		},
	}
	require.NoError(t, m.SetConfig(cfg))

	ws, err := m.Open(context.Background(), "tooled")
	require.NoError(t, err)

	assertToolAllowed(t, ws, "calendar.create", true, "calendar.create should be allowed")
	assertToolAllowed(t, ws, "shopping.list", true, "shopping.list should be allowed")
	assertToolAllowed(t, ws, "exec.run", false, "exec.run should be denied")
	assertToolAllowed(t, ws, "unknown.tool", false, "unknown.tool should not match allow list")
}

func TestManager_SetConfigRefreshesCachedPolicy(t *testing.T) {
	m := newTestManager(t)

	// Open workspace with initial config.
	cfg := workspace.Config{
		"ws": {
			Members: []string{"alice"},
			Tools: workspace.ToolConfig{
				Allow: []string{"calendar.*"},
			},
		},
	}
	require.NoError(t, m.SetConfig(cfg))

	ws, err := m.Open(context.Background(), "ws")
	require.NoError(t, err)
	assertToolAllowed(t, ws, "calendar.create", true, "initial config should allow calendar tools")
	assertToolAllowed(t, ws, "exec.run", false, "initial config should deny exec tools")

	// Update config to change the allow set — cached workspace should reflect the change.
	cfg2 := workspace.Config{
		"ws": {
			Members: []string{"alice"},
			Tools: workspace.ToolConfig{
				Allow: []string{"exec.*"},
				Deny:  []string{"calendar.*"},
			},
		},
	}
	require.NoError(t, m.SetConfig(cfg2))

	assertToolAllowed(t, ws, "exec.run", true, "updated config should allow exec tools")
	assertToolAllowed(t, ws, "calendar.create", false, "updated config should deny calendar tools")
}

func TestManager_PersonalWorkspaceIsUserScoped(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.SetConfig(workspace.Config{}))

	// Different users get different personal workspaces.
	ws1, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "T1",
		UserID:      "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal:alice", ws1.ID)

	ws2, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "T2",
		UserID:      "bob",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal:bob", ws2.ID)

	// They should be different instances.
	assert.NotSame(t, ws1, ws2)
}

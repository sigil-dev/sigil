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
	m.SetConfig(cfg)

	// Route a message from a bound channel.
	ws, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "slack",
		ChannelID:   "C001",
		UserID:      "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "work", ws.ID)

	// Unbound channel falls back to "personal" workspace.
	ws2, err := m.Route(context.Background(), workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "T999",
		UserID:      "charlie",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal", ws2.ID)
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
	m.SetConfig(cfg)

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
	m.SetConfig(cfg)

	ws, err := m.Open(context.Background(), "tooled")
	require.NoError(t, err)

	assert.True(t, ws.ToolAllowed("calendar.create"), "calendar.create should be allowed")
	assert.True(t, ws.ToolAllowed("shopping.list"), "shopping.list should be allowed")
	assert.False(t, ws.ToolAllowed("exec.run"), "exec.run should be denied")
	assert.False(t, ws.ToolAllowed("unknown.tool"), "unknown.tool should not match allow list")
}

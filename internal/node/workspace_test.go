// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceBinderBind(t *testing.T) {
	tests := []struct {
		name     string
		ws       string
		patterns []string
		wantErr  bool
		errCode  sigilerr.Code
	}{
		{
			name:     "valid patterns",
			ws:       "homelab",
			patterns: []string{"macbook-pro", "homelab-server"},
		},
		{
			name:     "glob pattern",
			ws:       "family",
			patterns: []string{"iphone-*"},
		},
		{
			name:     "empty workspace",
			ws:       "",
			patterns: []string{"node-a"},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "whitespace-only workspace",
			ws:       "  ",
			patterns: []string{"node-a"},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "empty patterns",
			ws:       "homelab",
			patterns: []string{},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "all-whitespace patterns",
			ws:       "homelab",
			patterns: []string{"", " "},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "invalid glob pattern",
			ws:       "homelab",
			patterns: []string{"["},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "pattern contains colon",
			ws:       "homelab",
			patterns: []string{"node:evil"},
			wantErr:  true,
			errCode:  sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:     "whitespace trimmed from valid inputs",
			ws:       " family ",
			patterns: []string{" iphone-* "},
		},
		{
			name:     "duplicate patterns deduplicated",
			ws:       "homelab",
			patterns: []string{"node-a", "node-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binder := node.NewWorkspaceBinder()
			err := binder.Bind(tt.ws, tt.patterns)

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.errCode))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestWorkspaceBinderBindWithTools(t *testing.T) {
	tests := []struct {
		name    string
		ws      string
		pattern string
		tools   []string
		wantErr bool
		errCode sigilerr.Code
	}{
		{
			name:    "valid binding with tools",
			ws:      "family",
			pattern: "iphone-*",
			tools:   []string{"camera", "location"},
		},
		{
			name:    "empty workspace",
			ws:      "",
			pattern: "iphone-*",
			tools:   []string{"camera"},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "empty pattern",
			ws:      "family",
			pattern: "",
			tools:   []string{"camera"},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "invalid glob pattern",
			ws:      "family",
			pattern: "[",
			tools:   []string{"camera"},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "pattern contains colon",
			ws:      "family",
			pattern: "iphone:evil",
			tools:   []string{"camera"},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "tool contains colon",
			ws:      "family",
			pattern: "iphone-*",
			tools:   []string{"camera:hd"},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "empty tools allowed",
			ws:      "family",
			pattern: "iphone-*",
			tools:   []string{},
		},
		{
			name:    "nil tools allowed",
			ws:      "family",
			pattern: "iphone-*",
			tools:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binder := node.NewWorkspaceBinder()
			err := binder.BindWithTools(tt.ws, tt.pattern, tt.tools)

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.errCode))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestWorkspaceBinderIsAllowed(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro", "homelab-server"}))
	require.NoError(t, binder.Bind("family", []string{"iphone-*"}))

	tests := []struct {
		name   string
		ws     string
		nodeID string
		want   bool
	}{
		{"exact match", "homelab", "macbook-pro", true},
		{"second exact match", "homelab", "homelab-server", true},
		{"glob match", "family", "iphone-sean", true},
		{"glob match variant", "family", "iphone-wife", true},
		{"wrong workspace", "homelab", "iphone-sean", false},
		{"cross-workspace isolation", "family", "macbook-pro", false},
		{"empty workspace", "", "macbook-pro", false},
		{"empty nodeID", "homelab", "", false},
		{"unbound workspace", "office", "macbook-pro", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, binder.IsAllowed(tt.ws, tt.nodeID))
		})
	}
}

func TestWorkspaceBinderAllowedTools(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*node.WorkspaceBinder)
		ws    string
		node  string
		want  []string
	}{
		{
			name: "tools from BindWithTools",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera", "location"}))
			},
			ws:   "family",
			node: "iphone-sean",
			want: []string{"node:iphone-sean:camera", "node:iphone-sean:location"},
		},
		{
			name: "no match returns nil",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera"}))
			},
			ws:   "family",
			node: "macbook-pro",
			want: nil,
		},
		{
			name: "Bind-only returns empty slice (all tools allowed)",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.Bind("homelab", []string{"macbook-*"}))
			},
			ws:   "homelab",
			node: "macbook-pro",
			want: []string{},
		},
		{
			name: "BindWithTools empty tools returns empty slice",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", nil))
			},
			ws:   "family",
			node: "iphone-sean",
			want: []string{},
		},
		{
			name: "dedup and sort across rules",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"location", "camera"}))
				require.NoError(t, b.BindWithTools("family", "iphone-sean", []string{"camera", "photos"}))
			},
			ws:   "family",
			node: "iphone-sean",
			want: []string{"node:iphone-sean:camera", "node:iphone-sean:location", "node:iphone-sean:photos"},
		},
		{
			name: "unrestricted Bind supersedes BindWithTools restrictions",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.Bind("ws", []string{"node-*"}))
				require.NoError(t, b.BindWithTools("ws", "node-a", []string{"camera"}))
			},
			ws:   "ws",
			node: "node-a",
			want: []string{},
		},
		{
			name: "empty workspace returns nil",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera"}))
			},
			ws:   "",
			node: "iphone-sean",
			want: nil,
		},
		{
			name: "empty nodeID returns nil",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera"}))
			},
			ws:   "family",
			node: "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binder := node.NewWorkspaceBinder()
			tt.setup(binder)

			got := binder.AllowedTools(tt.ws, tt.node)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWorkspaceBinderUnbind(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro"}))
	require.NoError(t, binder.BindWithTools("family", "iphone-*", []string{"camera"}))

	assert.True(t, binder.IsAllowed("homelab", "macbook-pro"))
	require.NoError(t, binder.Unbind("homelab"))
	assert.False(t, binder.IsAllowed("homelab", "macbook-pro"))

	// Family workspace unaffected.
	assert.True(t, binder.IsAllowed("family", "iphone-sean"))

	// Empty workspace returns error.
	err := binder.Unbind("")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindInvalidInput))
}

func TestWorkspaceBinderUnbindPattern(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro", "homelab-server"}))

	require.NoError(t, binder.UnbindPattern("homelab", "macbook-pro"))
	assert.False(t, binder.IsAllowed("homelab", "macbook-pro"))
	assert.True(t, binder.IsAllowed("homelab", "homelab-server"))

	// Remove last pattern removes workspace entry.
	require.NoError(t, binder.UnbindPattern("homelab", "homelab-server"))
	assert.False(t, binder.IsAllowed("homelab", "homelab-server"))

	// Empty inputs return errors.
	err := binder.UnbindPattern("", "pattern")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindInvalidInput))

	err = binder.UnbindPattern("ws", "")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindInvalidInput))
}

func TestWorkspaceBinderValidateWorkspace(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro"}))

	assert.NoError(t, binder.ValidateWorkspace("macbook-pro", "homelab"))

	err := binder.ValidateWorkspace("unknown-node", "homelab")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeWorkspaceMembershipDenied))
}

func TestWorkspaceBinderNormalizesInputs(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	require.NoError(t, binder.Bind(" family ", []string{" iphone-* ", "", "iphone-*"}))
	require.NoError(t, binder.BindWithTools(" family ", " iphone-* ", []string{" location ", "", "camera", "camera"}))

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
	// Unrestricted Bind supersedes BindWithTools restrictions.
	assert.Equal(t, []string{}, binder.AllowedTools("family", "iphone-sean"))
}

func TestWorkspaceBinderCrossWorkspaceIsolation(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro"}))
	require.NoError(t, binder.Bind("family", []string{"iphone-*"}))

	assert.False(t, binder.IsAllowed("family", "macbook-pro"),
		"node bound to homelab must not appear in family")
	assert.False(t, binder.IsAllowed("homelab", "iphone-sean"),
		"node bound to family must not appear in homelab")
	assert.Nil(t, binder.AllowedTools("family", "macbook-pro"))
	assert.Nil(t, binder.AllowedTools("homelab", "iphone-sean"))
}

func TestWorkspaceBinderConcurrentAccess(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			_ = binder.Bind("ws", []string{"node-*"})
		}()
		go func() {
			defer wg.Done()
			binder.IsAllowed("ws", "node-1")
		}()
		go func() {
			defer wg.Done()
			binder.AllowedTools("ws", "node-1")
		}()
		go func() {
			defer wg.Done()
			_ = binder.Unbind("ws-ephemeral")
		}()
		go func() {
			defer wg.Done()
			_ = binder.UnbindPattern("ws", "node-gone")
		}()
	}
	wg.Wait()

	assert.True(t, binder.IsAllowed("ws", "node-1"))
}

func TestWorkspaceBinderCheckLimits(t *testing.T) {
	t.Run("per-workspace rule limit exceeded", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		// Fill up to the limit with batches.
		patterns := make([]string, 500)
		for i := range patterns {
			patterns[i] = fmt.Sprintf("node-%04d", i)
		}
		require.NoError(t, binder.Bind("ws", patterns))

		// One more should fail.
		err := binder.Bind("ws", []string{"node-overflow"})
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindLimitExceeded))
	})

	t.Run("BindWithTools also respects per-workspace limit", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		patterns := make([]string, 500)
		for i := range patterns {
			patterns[i] = fmt.Sprintf("node-%04d", i)
		}
		require.NoError(t, binder.Bind("ws", patterns))

		err := binder.BindWithTools("ws", "node-extra", []string{"tool"})
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindLimitExceeded))
	})

	t.Run("workspace count limit exceeded", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		for i := 0; i < 1000; i++ {
			require.NoError(t, binder.Bind(fmt.Sprintf("ws-%04d", i), []string{"node-a"}))
		}

		err := binder.Bind("ws-overflow", []string{"node-a"})
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindLimitExceeded))
	})

	t.Run("duplicate patterns deduplicated against stored rules", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		require.NoError(t, binder.Bind("ws", []string{"node-a", "node-b"}))

		// Re-binding same patterns should be a no-op (no duplicates stored).
		require.NoError(t, binder.Bind("ws", []string{"node-a"}))

		// node-a should still work and only one rule exists for it.
		assert.True(t, binder.IsAllowed("ws", "node-a"))
		assert.True(t, binder.IsAllowed("ws", "node-b"))

		// Fill to near-limit, then verify re-binding existing doesn't fail.
		patterns := make([]string, 498)
		for i := range patterns {
			patterns[i] = fmt.Sprintf("node-%04d", i)
		}
		require.NoError(t, binder.Bind("ws", patterns))

		// Re-binding an existing pattern should succeed (dedup makes count 0).
		require.NoError(t, binder.Bind("ws", []string{"node-a"}))
	})

	t.Run("existing workspace unaffected after limit error", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		patterns := make([]string, 500)
		for i := range patterns {
			patterns[i] = fmt.Sprintf("node-%04d", i)
		}
		require.NoError(t, binder.Bind("ws", patterns))

		// Overflow attempt fails.
		err := binder.Bind("ws", []string{"node-overflow"})
		require.Error(t, err)

		// Original bindings still intact.
		assert.True(t, binder.IsAllowed("ws", "node-0000"))
		assert.True(t, binder.IsAllowed("ws", "node-0499"))
		assert.False(t, binder.IsAllowed("ws", "node-overflow"))
	})
}

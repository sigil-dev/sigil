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
			name:    "empty tools rejected",
			ws:      "family",
			pattern: "iphone-*",
			tools:   []string{},
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name:    "nil tools rejected",
			ws:      "family",
			pattern: "iphone-*",
			tools:   nil,
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
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
		name    string
		setup   func(*node.WorkspaceBinder)
		ws      string
		node    string
		want    []string
		wantErr bool
		errCode sigilerr.Code
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
			name: "BindWithTools before Bind: unrestricted still supersedes",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("ws", "node-a", []string{"camera"}))
				require.NoError(t, b.Bind("ws", []string{"node-*"}))
			},
			ws:   "ws",
			node: "node-a",
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
			name: "empty workspace returns error",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera"}))
			},
			ws:      "",
			node:    "iphone-sean",
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
		{
			name: "empty nodeID returns error",
			setup: func(b *node.WorkspaceBinder) {
				require.NoError(t, b.BindWithTools("family", "iphone-*", []string{"camera"}))
			},
			ws:      "family",
			node:    "",
			wantErr: true,
			errCode: sigilerr.CodeNodeBindInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binder := node.NewWorkspaceBinder()
			tt.setup(binder)

			got, err := binder.AllowedTools(tt.ws, tt.node)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.errCode))
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
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

	// Idempotent: Unbind on never-bound workspace is a no-op.
	require.NoError(t, binder.Unbind("never-bound"))

	// Idempotent: second Unbind after already removed is a no-op.
	require.NoError(t, binder.Unbind("homelab"))
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

	// Idempotent: UnbindPattern on never-bound workspace is a no-op.
	require.NoError(t, binder.UnbindPattern("never-bound", "any-pattern"))

	// Idempotent: UnbindPattern with non-matching pattern preserves existing rules.
	binder2 := node.NewWorkspaceBinder()
	require.NoError(t, binder2.Bind("ws", []string{"node-a"}))
	require.NoError(t, binder2.UnbindPattern("ws", "does-not-exist"))
	assert.True(t, binder2.IsAllowed("ws", "node-a"))

	// Cross-type: UnbindPattern removes BindWithTools rules.
	binder3 := node.NewWorkspaceBinder()
	require.NoError(t, binder3.BindWithTools("ws", "node-a", []string{"camera"}))
	require.NoError(t, binder3.UnbindPattern("ws", "node-a"))
	got, err := binder3.AllowedTools("ws", "node-a")
	require.NoError(t, err)
	assert.Nil(t, got, "AllowedTools should return nil after UnbindPattern removes BindWithTools rule")

	// Cross-type: mixed Bind+BindWithTools, UnbindPattern removes both.
	binder4 := node.NewWorkspaceBinder()
	require.NoError(t, binder4.Bind("ws", []string{"node-a"}))
	require.NoError(t, binder4.BindWithTools("ws", "node-a", []string{"camera"}))
	require.NoError(t, binder4.UnbindPattern("ws", "node-a"))
	assert.False(t, binder4.IsAllowed("ws", "node-a"))
	got, err = binder4.AllowedTools("ws", "node-a")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestWorkspaceBinderValidateWorkspace(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro"}))

	assert.NoError(t, binder.ValidateWorkspace("macbook-pro", "homelab"))

	// Denied node returns correct code and structured fields.
	err := binder.ValidateWorkspace("unknown-node", "homelab")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeWorkspaceMembershipDenied))
	fields := sigilerr.FieldsOf(err)
	assert.Equal(t, "unknown-node", fields["node_id"])
	assert.Equal(t, "homelab", fields["workspace_id"])

	// Empty nodeID returns input error, not membership denied.
	err = binder.ValidateWorkspace("", "homelab")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindInvalidInput))

	// Empty workspaceID returns input error.
	err = binder.ValidateWorkspace("macbook-pro", "")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindInvalidInput))
}

func TestWorkspaceBinderNormalizesInputs(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	require.NoError(t, binder.Bind(" family ", []string{" iphone-* ", "", "iphone-*"}))
	require.NoError(t, binder.BindWithTools(" family ", " iphone-* ", []string{" location ", "", "camera", "camera"}))

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
	// Unrestricted Bind supersedes BindWithTools restrictions.
	got, err := binder.AllowedTools("family", "iphone-sean")
	require.NoError(t, err)
	assert.Equal(t, []string{}, got)
}

func TestWorkspaceBinderCrossWorkspaceIsolation(t *testing.T) {
	binder := node.NewWorkspaceBinder()
	require.NoError(t, binder.Bind("homelab", []string{"macbook-pro"}))
	require.NoError(t, binder.Bind("family", []string{"iphone-*"}))

	assert.False(t, binder.IsAllowed("family", "macbook-pro"),
		"node bound to homelab must not appear in family")
	assert.False(t, binder.IsAllowed("homelab", "iphone-sean"),
		"node bound to family must not appear in homelab")
	got, err := binder.AllowedTools("family", "macbook-pro")
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = binder.AllowedTools("homelab", "iphone-sean")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestWorkspaceBinderConcurrentAccess(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(6)
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
			_, _ = binder.AllowedTools("ws", "node-1")
		}()
		go func() {
			defer wg.Done()
			_ = binder.Unbind("ws-ephemeral")
		}()
		go func() {
			defer wg.Done()
			_ = binder.UnbindPattern("ws", "node-gone")
		}()
		go func() {
			defer wg.Done()
			_ = binder.BindWithTools("ws", "tool-node", []string{fmt.Sprintf("tool-%d", i)})
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

	t.Run("BindWithTools workspace count limit exceeded", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		for i := 0; i < 1000; i++ {
			require.NoError(t, binder.Bind(fmt.Sprintf("ws-%04d", i), []string{"node-a"}))
		}

		err := binder.BindWithTools("ws-overflow", "node-a", []string{"camera"})
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

	t.Run("BindWithTools per-workspace limit exhausted by unique tool sets", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		// Each BindWithTools call with a unique tool set consumes one slot.
		for i := 0; i < 500; i++ {
			require.NoError(t, binder.BindWithTools("ws", "node-a", []string{fmt.Sprintf("tool-%04d", i)}))
		}
		// 501st call with a new tool set exceeds the limit.
		err := binder.BindWithTools("ws", "node-a", []string{"tool-overflow"})
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeNodeBindLimitExceeded))

		// Duplicate call (same pattern+tools) should still succeed via dedup.
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"tool-0000"}))
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

func TestWorkspaceBinderBindWithToolsAccumulation(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	// Duplicate BindWithTools calls accumulate (additive semantics).
	require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera"}))
	require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera", "location"}))

	// AllowedTools merges and deduplicates across accumulated rules.
	got, err := binder.AllowedTools("ws", "node-a")
	require.NoError(t, err)
	assert.Equal(t, []string{"node:node-a:camera", "node:node-a:location"}, got)
}

func TestWorkspaceBinderBindWithToolsDeduplication(t *testing.T) {
	t.Run("identical pattern+tools is no-op", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera"}))
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera"}))

		got, err := binder.AllowedTools("ws", "node-a")
		require.NoError(t, err)
		assert.Equal(t, []string{"node:node-a:camera"}, got)
	})

	t.Run("different tools still accumulates", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera"}))
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"location"}))

		got, err := binder.AllowedTools("ws", "node-a")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"node:node-a:camera", "node:node-a:location"}, got)
	})

	t.Run("same tools different order is no-op", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"camera", "location"}))
		require.NoError(t, binder.BindWithTools("ws", "node-a", []string{"location", "camera"}))

		got, err := binder.AllowedTools("ws", "node-a")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"node:node-a:camera", "node:node-a:location"}, got)
	})

	t.Run("dedup prevents limit exhaustion", func(t *testing.T) {
		binder := node.NewWorkspaceBinder()
		// Fill workspace near limit with unique patterns.
		for i := 0; i < 499; i++ {
			require.NoError(t, binder.Bind("ws", []string{fmt.Sprintf("node-%04d", i)}))
		}
		// Add one BindWithTools rule.
		require.NoError(t, binder.BindWithTools("ws", "node-last", []string{"camera"}))
		// Re-adding the same rule should succeed (dedup, no slot consumed).
		require.NoError(t, binder.BindWithTools("ws", "node-last", []string{"camera"}))
	})
}

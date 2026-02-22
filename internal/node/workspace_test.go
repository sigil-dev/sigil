// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	"github.com/stretchr/testify/assert"
)

func TestWorkspaceBinderBind(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.Bind("homelab", []string{"macbook-pro", "homelab-server"})
	binder.Bind("family", []string{"iphone-*"})

	assert.True(t, binder.IsAllowed("homelab", "macbook-pro"))
	assert.True(t, binder.IsAllowed("homelab", "homelab-server"))
	assert.False(t, binder.IsAllowed("homelab", "iphone-sean"))

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	assert.True(t, binder.IsAllowed("family", "iphone-wife"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
}

func TestWorkspaceBinderBindWithTools(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.BindWithTools("family", "iphone-*", []string{"camera", "location"})

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	tools := binder.AllowedTools("family", "iphone-sean")
	assert.ElementsMatch(t, []string{
		"node:iphone-sean:camera",
		"node:iphone-sean:location",
	}, tools)
	assert.NotContains(t, tools, "node:iphone-sean:filesystem")

	assert.Empty(t, binder.AllowedTools("family", "macbook-pro"))
}

func TestWorkspaceBinderAllowedToolsDedupAndSortAcrossRules(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.BindWithTools("family", "iphone-*", []string{"location", "camera"})
	binder.BindWithTools("family", "iphone-sean", []string{"camera", "photos"})

	tools := binder.AllowedTools("family", "iphone-sean")
	assert.Equal(t, []string{
		"node:iphone-sean:camera",
		"node:iphone-sean:location",
		"node:iphone-sean:photos",
	}, tools)
}

func TestWorkspaceBinderNormalizesAndIgnoresInvalidEntries(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.Bind(" family ", []string{" iphone-* ", "", "iphone-*"})
	binder.Bind("family", []string{"["})
	binder.BindWithTools(" family ", " iphone-* ", []string{" location ", "", "camera", "camera"})
	binder.BindWithTools("family", "", []string{"camera"})
	binder.BindWithTools("", "iphone-*", []string{"camera"})

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
	assert.Equal(t, []string{
		"node:iphone-sean:camera",
		"node:iphone-sean:location",
	}, binder.AllowedTools("family", "iphone-sean"))
}

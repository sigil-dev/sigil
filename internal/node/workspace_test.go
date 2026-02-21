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

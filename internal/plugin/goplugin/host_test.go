// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package goplugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin/goplugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_HandshakeConfig(t *testing.T) {
	config := goplugin.HandshakeConfig()
	assert.NotEmpty(t, config.ProtocolVersion)
	assert.NotEmpty(t, config.MagicCookieKey)
	assert.NotEmpty(t, config.MagicCookieValue)
}

func TestHost_PluginMap(t *testing.T) {
	pm := goplugin.PluginMap()
	require.NotNil(t, pm)

	_, ok := pm["lifecycle"]
	assert.True(t, ok)
	_, ok = pm["channel"]
	assert.True(t, ok)
	_, ok = pm["tool"]
	assert.True(t, ok)
	_, ok = pm["provider"]
	assert.True(t, ok)
}

func TestHost_NewClient(t *testing.T) {
	config := goplugin.ClientConfig("/nonexistent/binary", nil)
	assert.NotNil(t, config)
	assert.Equal(t, "/nonexistent/binary", config.Cmd.Path)
}

func TestHost_ClientConfig_WithSandbox(t *testing.T) {
	sandboxCmd := []string{"bwrap", "--ro-bind", "/usr", "/usr"}
	config := goplugin.ClientConfig("/nonexistent/binary", sandboxCmd)
	assert.NotNil(t, config)
	assert.Equal(t, "bwrap", config.Cmd.Path)
}

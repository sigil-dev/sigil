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

func TestHost_BuildCommand_NoSliceMutation(t *testing.T) {
	// Regression: append(sandboxCmd, binaryPath) could mutate the caller's
	// slice when spare capacity exists.
	sandboxCmd := make([]string, 3, 10) // spare capacity
	sandboxCmd[0] = "bwrap"
	sandboxCmd[1] = "--ro-bind"
	sandboxCmd[2] = "/usr"

	original := make([]string, len(sandboxCmd))
	copy(original, sandboxCmd)

	_ = goplugin.ClientConfig("/my/binary", sandboxCmd)

	// The caller's slice must not be mutated.
	assert.Equal(t, original, sandboxCmd,
		"buildCommand must not mutate the caller's sandboxCmd slice")
}

func TestHost_PluginWrappers_NetRPCReturnsError(t *testing.T) {
	// Verify plugin wrappers use NetRPCUnsupportedPlugin (returns errors)
	// instead of raw plugin.Plugin interface (would panic on nil methods).
	pm := goplugin.PluginMap()

	for name, p := range pm {
		t.Run(name, func(t *testing.T) {
			// Call the Server method with nil — NetRPCUnsupportedPlugin returns an error,
			// whereas the raw interface embedding would panic.
			_, err := p.Server(nil)
			assert.Error(t, err, "NetRPCUnsupportedPlugin.Server should return error, not panic")
		})
	}
}

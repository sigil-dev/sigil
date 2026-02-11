// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseManifest_Valid(t *testing.T) {
	yaml := `
name: telegram-channel
version: 1.2.0
type: channel
engine: ">= 1.0.0"
license: MIT
capabilities:
  - sessions.read
  - sessions.write
  - messages.send
deny_capabilities:
  - exec.*
execution:
  tier: process
  sandbox:
    network:
      allow:
        - api.telegram.org:443
lifecycle:
  hot_reload: true
  graceful_shutdown_timeout: 30s
`
	m, err := plugin.ParseManifest([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "telegram-channel", m.Name)
	assert.Equal(t, "1.2.0", m.Version)
	assert.Equal(t, plugin.TypeChannel, m.Type)
	assert.Equal(t, plugin.TierProcess, m.Execution.Tier)
	assert.Contains(t, m.Capabilities, "sessions.read")
	assert.Contains(t, m.DenyCapabilities, "exec.*")
	assert.True(t, m.Lifecycle.HotReload)
}

func TestParseManifest_InvalidType(t *testing.T) {
	yaml := `
name: bad-plugin
version: 1.0.0
type: invalid
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestParseManifest_MissingName(t *testing.T) {
	yaml := `
version: 1.0.0
type: tool
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
}

func TestParseManifest_InvalidTier(t *testing.T) {
	yaml := `
name: bad-tier
version: 1.0.0
type: tool
execution:
  tier: quantum
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
}

func TestValidateManifest_ConflictingCapabilities(t *testing.T) {
	m := &plugin.Manifest{
		Name:             "conflict",
		Version:          "1.0.0",
		Type:             plugin.TypeTool,
		Capabilities:     []string{"exec.run"},
		DenyCapabilities: []string{"exec.*"},
		Execution:        plugin.ExecutionConfig{Tier: plugin.TierProcess},
	}

	errs := m.Validate()
	assert.NotEmpty(t, errs)
}

// NOTE: These are internal runtime types (plugin.TypeChannel, plugin.TierProcess),
// distinct from the public SDK types in pkg/plugin (plugin.PluginTypeChannel, plugin.ExecutionTierProcess).
// The internal types use simplified string constants for efficient runtime matching.

func TestPluginTypeValues(t *testing.T) {
	assert.Equal(t, plugin.PluginType("provider"), plugin.TypeProvider)
	assert.Equal(t, plugin.PluginType("channel"), plugin.TypeChannel)
	assert.Equal(t, plugin.PluginType("tool"), plugin.TypeTool)
	assert.Equal(t, plugin.PluginType("skill"), plugin.TypeSkill)
}

func TestExecutionTierValues(t *testing.T) {
	assert.Equal(t, plugin.ExecutionTier("wasm"), plugin.TierWasm)
	assert.Equal(t, plugin.ExecutionTier("process"), plugin.TierProcess)
	assert.Equal(t, plugin.ExecutionTier("container"), plugin.TierContainer)
}

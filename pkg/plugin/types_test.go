// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestPluginTypeValues(t *testing.T) {
	assert.Equal(t, plugin.PluginType("provider"), plugin.PluginTypeProvider)
	assert.Equal(t, plugin.PluginType("channel"), plugin.PluginTypeChannel)
	assert.Equal(t, plugin.PluginType("tool"), plugin.PluginTypeTool)
	assert.Equal(t, plugin.PluginType("skill"), plugin.PluginTypeSkill)
}

func TestExecutionTierValues(t *testing.T) {
	assert.Equal(t, plugin.ExecutionTier("wasm"), plugin.ExecutionTierWasm)
	assert.Equal(t, plugin.ExecutionTier("process"), plugin.ExecutionTierProcess)
	assert.Equal(t, plugin.ExecutionTier("container"), plugin.ExecutionTierContainer)
}

func TestManifestFields(t *testing.T) {
	manifest := plugin.Manifest{
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    plugin.PluginTypeChannel,
		Execution: plugin.ExecutionConfig{
			Tier: plugin.ExecutionTierProcess,
		},
		Capabilities: []plugin.Capability{
			{Pattern: "channel:send"},
		},
	}
	assert.Equal(t, "test-plugin", manifest.Name)
	assert.Equal(t, plugin.PluginTypeChannel, manifest.Type)
	assert.Len(t, manifest.Capabilities, 1)
}

func TestCapabilityPattern(t *testing.T) {
	cap := plugin.Capability{
		Pattern:     "sessions.read",
		Description: "Read session data",
	}
	assert.Equal(t, "sessions.read", cap.Pattern)
}

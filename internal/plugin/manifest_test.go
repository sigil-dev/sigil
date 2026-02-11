// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"strings"
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

func TestValidateManifest_CapabilitySegmentLimit(t *testing.T) {
	// Build a 33-segment capability pattern that would cause MatchCapability
	// to return an error. Manifest validation must catch this at load time
	// so enforcement never encounters it.
	segments := make([]string, 33)
	for i := range segments {
		segments[i] = "a"
	}
	longPattern := strings.Join(segments, ".")

	m := &plugin.Manifest{
		Name:         "segment-test",
		Version:      "1.0.0",
		Type:         plugin.TypeTool,
		Capabilities: []string{longPattern},
		Execution:    plugin.ExecutionConfig{Tier: plugin.TierProcess},
	}

	errs := m.Validate()
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "exceeds maximum 32 segments")
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

func TestValidateManifest_SemverVersionField(t *testing.T) {
	base := plugin.Manifest{
		Name:      "test",
		Type:      plugin.TypeTool,
		Execution: plugin.ExecutionConfig{Tier: plugin.TierProcess},
	}

	valid := []string{
		"1.0.0",
		"0.1.0",
		"2.3.4-beta.1",
		"1.0.0+build.123",
		"10.20.30-alpha.1+meta",
	}
	for _, v := range valid {
		t.Run("valid_"+v, func(t *testing.T) {
			m := base
			m.Version = v
			errs := m.Validate()
			for _, e := range errs {
				assert.NotContains(t, e.Error(), "version", "version %q should be valid", v)
			}
		})
	}

	invalid := []string{
		"latest",
		"1.0",
		"v1.0.0",
		"1",
		"1.0.0.0",
		"01.0.0",
		"1.02.0",
		"-1.0.0",
	}
	for _, v := range invalid {
		t.Run("invalid_"+v, func(t *testing.T) {
			m := base
			m.Version = v
			errs := m.Validate()
			found := false
			for _, e := range errs {
				if strings.Contains(e.Error(), "version must be valid semver") {
					found = true
				}
			}
			assert.True(t, found, "version %q should fail semver validation", v)
		})
	}
}

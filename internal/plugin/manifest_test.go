// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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
	m, errs := plugin.ParseManifest([]byte(yaml))
	require.Empty(t, errs)
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
execution:
  tier: process
`
	_, errs := plugin.ParseManifest([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "type")
	assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid),
		"manifest type validation error should have CodePluginManifestValidateInvalid")
}

func TestParseManifest_MissingName(t *testing.T) {
	yaml := `
version: 1.0.0
type: tool
execution:
  tier: process
`
	_, errs := plugin.ParseManifest([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid),
		"missing name error should have CodePluginManifestValidateInvalid")
}

func TestParseManifest_InvalidTier(t *testing.T) {
	yaml := `
name: bad-tier
version: 1.0.0
type: tool
execution:
  tier: quantum
`
	_, errs := plugin.ParseManifest([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid),
		"invalid tier error should have CodePluginManifestValidateInvalid")
}

func TestParseManifest_ContainerExecutionFields(t *testing.T) {
	yaml := `
name: python-tool
version: 1.0.0
type: tool
execution:
  tier: container
  image: ghcr.io/org/python-tool:latest
  network: restricted
  memory_limit: 256Mi
capabilities:
  - tools.execute
`
	m, errs := plugin.ParseManifest([]byte(yaml))
	require.Empty(t, errs)
	assert.Equal(t, plugin.TierContainer, m.Execution.Tier)
	assert.Equal(t, "ghcr.io/org/python-tool:latest", m.Execution.Image)
	assert.Equal(t, "restricted", m.Execution.Network)
	assert.Equal(t, "256Mi", m.Execution.MemoryLimit)
}

func TestParseManifest_ContainerExecutionValidation(t *testing.T) {
	t.Run("missing image", func(t *testing.T) {
		yaml := `
name: python-tool
version: 1.0.0
type: tool
execution:
  tier: container
  network: restricted
  memory_limit: 256Mi
capabilities:
  - tools.execute
`
		_, errs := plugin.ParseManifest([]byte(yaml))
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.image")
	})

	t.Run("missing memory limit", func(t *testing.T) {
		yaml := `
name: python-tool
version: 1.0.0
type: tool
execution:
  tier: container
  image: ghcr.io/org/python-tool:latest
  network: restricted
capabilities:
  - tools.execute
`
		_, errs := plugin.ParseManifest([]byte(yaml))
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.memory_limit")
	})

	t.Run("invalid network mode", func(t *testing.T) {
		yaml := `
name: python-tool
version: 1.0.0
type: tool
execution:
  tier: container
  image: ghcr.io/org/python-tool:latest
  network: open
  memory_limit: 256Mi
capabilities:
  - tools.execute
`
		_, errs := plugin.ParseManifest([]byte(yaml))
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.network")
	})

	t.Run("image with embedded tab character", func(t *testing.T) {
		// Use struct construction so the tab survives without YAML escaping issues.
		// The tab is embedded mid-string so TrimSpace does not remove it.
		m := &plugin.Manifest{
			Name:    "python-tool",
			Version: "1.0.0",
			Type:    plugin.TypeTool,
			Execution: plugin.ExecutionConfig{
				Tier:        plugin.TierContainer,
				Image:       "ghcr.io/org/tool\t:v1",
				MemoryLimit: "256Mi",
			},
			Capabilities: []string{"tools.execute"},
		}
		errs := m.Validate()
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.image")
	})

	t.Run("image with embedded newline character", func(t *testing.T) {
		// Use struct construction so the newline survives without YAML escaping issues.
		// The newline is embedded mid-string so TrimSpace does not remove it.
		m := &plugin.Manifest{
			Name:    "python-tool",
			Version: "1.0.0",
			Type:    plugin.TypeTool,
			Execution: plugin.ExecutionConfig{
				Tier:        plugin.TierContainer,
				Image:       "ghcr.io/org/tool\n:v1",
				MemoryLimit: "256Mi",
			},
			Capabilities: []string{"tools.execute"},
		}
		errs := m.Validate()
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.image")
	})

	t.Run("path-prefix image rejected as non-OCI reference", func(t *testing.T) {
		yaml := `
name: python-tool
version: 1.0.0
type: tool
execution:
  tier: container
  image: ./local
  memory_limit: 256Mi
capabilities:
  - tools.execute
`
		_, errs := plugin.ParseManifest([]byte(yaml))
		require.NotEmpty(t, errs)
		assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid))
		combined := ""
		for _, e := range errs {
			combined += e.Error()
		}
		assert.Contains(t, combined, "execution.image")
	})
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
	assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid),
		"conflicting capabilities error should have CodePluginManifestValidateInvalid")
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
	assert.True(t, sigilerr.HasCode(errs[0], sigilerr.CodePluginManifestValidateInvalid),
		"segment limit error should have CodePluginManifestValidateInvalid")
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

func TestValidateManifest_MalformedTimeout(t *testing.T) {
	base := plugin.Manifest{
		Name:      "timeout-test",
		Version:   "1.0.0",
		Type:      plugin.TypeTool,
		Execution: plugin.ExecutionConfig{Tier: plugin.TierProcess},
	}

	tests := []struct {
		name    string
		timeout string
		wantErr bool
	}{
		{"valid duration", "30s", false},
		{"valid duration minutes", "5m", false},
		{"invalid format", "not-a-duration", true},
		{"invalid format abc", "abc", true},
		{"negative duration", "-1s", true},
		{"empty string", "", false}, // empty is OK (optional field)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base
			m.Lifecycle = plugin.LifecycleConfig{GracefulShutdownTimeout: tt.timeout}
			errs := m.Validate()

			if tt.wantErr {
				require.NotEmpty(t, errs, "expected validation error for timeout %q", tt.timeout)
				found := false
				for _, e := range errs {
					if strings.Contains(e.Error(), "graceful_shutdown_timeout") {
						found = true
						assert.True(t, sigilerr.HasCode(e, sigilerr.CodePluginManifestValidateInvalid),
							"timeout error should have CodePluginManifestValidateInvalid")
						break
					}
				}
				assert.True(t, found, "timeout error not found for %q", tt.timeout)
			} else {
				// Filter out errors that are not about timeout
				for _, e := range errs {
					assert.NotContains(t, e.Error(), "graceful_shutdown_timeout", "unexpected timeout error for %q", tt.timeout)
				}
			}
		})
	}
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
					assert.True(t, sigilerr.HasCode(e, sigilerr.CodePluginManifestValidateInvalid),
						"semver error should have CodePluginManifestValidateInvalid")
				}
			}
			assert.True(t, found, "version %q should fail semver validation", v)
		})
	}
}

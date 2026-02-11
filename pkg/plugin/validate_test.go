// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validManifest returns a minimal valid Manifest for testing.
// Tests modify specific fields to trigger validation failures.
func validManifest() plugin.Manifest {
	return plugin.Manifest{
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    plugin.PluginTypeTool,
		Capabilities: []plugin.Capability{
			{Pattern: "sessions.read"},
		},
		Execution: plugin.ExecutionConfig{
			Tier: plugin.ExecutionTierProcess,
		},
	}
}

func TestManifestValidate(t *testing.T) {
	t.Run("valid manifests", func(t *testing.T) {
		tests := []struct {
			name     string
			manifest plugin.Manifest
		}{
			{
				name:     "minimal valid manifest",
				manifest: validManifest(),
			},
			{
				name: "all plugin types - provider",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Type = plugin.PluginTypeProvider
					return m
				}(),
			},
			{
				name: "all plugin types - channel",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Type = plugin.PluginTypeChannel
					return m
				}(),
			},
			{
				name: "all plugin types - skill",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Type = plugin.PluginTypeSkill
					return m
				}(),
			},
			{
				name: "all execution tiers - wasm",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Execution.Tier = plugin.ExecutionTierWasm
					return m
				}(),
			},
			{
				name: "all execution tiers - container",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Execution.Tier = plugin.ExecutionTierContainer
					return m
				}(),
			},
			{
				name: "version with pre-release",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Version = "1.0.0-alpha.1"
					return m
				}(),
			},
			{
				name: "version with build metadata",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Version = "1.0.0+build.123"
					return m
				}(),
			},
			{
				name: "version with pre-release and build metadata",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Version = "2.1.3-beta.2+build.456"
					return m
				}(),
			},
			{
				name: "empty capabilities list",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Capabilities = nil
					return m
				}(),
			},
			{
				name: "multiple capabilities",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Capabilities = []plugin.Capability{
						{Pattern: "sessions.read"},
						{Pattern: "sessions.write.self"},
						{Pattern: "messages.send.*"},
					}
					return m
				}(),
			},
			{
				name: "glob capability with wildcard",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Capabilities = []plugin.Capability{
						{Pattern: "kv.*"},
					}
					return m
				}(),
			},
			{
				name: "path-scoped capability",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Capabilities = []plugin.Capability{
						{Pattern: "filesystem.read./data/*"},
					}
					return m
				}(),
			},
			{
				name: "deny capabilities that don't conflict",
				manifest: func() plugin.Manifest {
					m := validManifest()
					m.Capabilities = []plugin.Capability{
						{Pattern: "sessions.read"},
					}
					m.DenyCapabilities = []plugin.Capability{
						{Pattern: "exec.*"},
					}
					return m
				}(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := (&tt.manifest).Validate()
				assert.NoError(t, err)
			})
		}
	})

	t.Run("name validation", func(t *testing.T) {
		tests := []struct {
			name    string
			setName string
			wantErr string
		}{
			{
				name:    "empty name",
				setName: "",
				wantErr: "name must not be empty",
			},
			{
				name:    "whitespace-only name",
				setName: "   ",
				wantErr: "name must not be empty",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Name = tt.setName
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("version validation", func(t *testing.T) {
		tests := []struct {
			name       string
			setVersion string
			wantErr    string
		}{
			{
				name:       "empty version",
				setVersion: "",
				wantErr:    "version must not be empty",
			},
			{
				name:       "missing minor and patch",
				setVersion: "1",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "missing patch",
				setVersion: "1.0",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "leading v prefix",
				setVersion: "v1.0.0",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "non-numeric version",
				setVersion: "one.two.three",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "negative number",
				setVersion: "-1.0.0",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "trailing text",
				setVersion: "1.0.0.0",
				wantErr:    "version must be valid semver",
			},
			{
				name:       "leading zero major",
				setVersion: "01.0.0",
				wantErr:    "version must be valid semver",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Version = tt.setVersion
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("type validation", func(t *testing.T) {
		tests := []struct {
			name    string
			setType plugin.PluginType
			wantErr string
		}{
			{
				name:    "empty type",
				setType: "",
				wantErr: "type must be one of",
			},
			{
				name:    "unknown type",
				setType: "unknown",
				wantErr: "type must be one of",
			},
			{
				name:    "capitalized type",
				setType: "Provider",
				wantErr: "type must be one of",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Type = tt.setType
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("capability validation", func(t *testing.T) {
		tests := []struct {
			name    string
			caps    []plugin.Capability
			wantErr string
		}{
			{
				name: "empty pattern",
				caps: []plugin.Capability{
					{Pattern: ""},
				},
				wantErr: "capability pattern must not be empty",
			},
			{
				name: "pattern with spaces",
				caps: []plugin.Capability{
					{Pattern: "sessions read"},
				},
				wantErr: "contains invalid characters",
			},
			{
				name: "pattern with consecutive dots",
				caps: []plugin.Capability{
					{Pattern: "sessions..read"},
				},
				wantErr: "contains consecutive dots",
			},
			{
				name: "pattern starting with dot",
				caps: []plugin.Capability{
					{Pattern: ".sessions.read"},
				},
				wantErr: "must not start or end with a dot",
			},
			{
				name: "pattern ending with dot",
				caps: []plugin.Capability{
					{Pattern: "sessions.read."},
				},
				wantErr: "must not start or end with a dot",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Capabilities = tt.caps
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("deny capability validation", func(t *testing.T) {
		tests := []struct {
			name     string
			caps     []plugin.Capability
			denyCaps []plugin.Capability
			wantErr  string
		}{
			{
				name: "malformed deny pattern",
				caps: []plugin.Capability{
					{Pattern: "sessions.read"},
				},
				denyCaps: []plugin.Capability{
					{Pattern: ""},
				},
				wantErr: "deny capability pattern must not be empty",
			},
			{
				name: "exact conflict between grant and deny",
				caps: []plugin.Capability{
					{Pattern: "exec.run"},
				},
				denyCaps: []plugin.Capability{
					{Pattern: "exec.run"},
				},
				wantErr: "conflicts with granted capability",
			},
			{
				name: "deny glob covers granted capability",
				caps: []plugin.Capability{
					{Pattern: "exec.run"},
				},
				denyCaps: []plugin.Capability{
					{Pattern: "exec.*"},
				},
				wantErr: "conflicts with granted capability",
			},
			{
				name: "granted glob covers denied capability",
				caps: []plugin.Capability{
					{Pattern: "exec.*"},
				},
				denyCaps: []plugin.Capability{
					{Pattern: "exec.run"},
				},
				wantErr: "conflicts with granted capability",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Capabilities = tt.caps
				m.DenyCapabilities = tt.denyCaps
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("execution tier validation", func(t *testing.T) {
		tests := []struct {
			name    string
			setTier plugin.ExecutionTier
			wantErr string
		}{
			{
				name:    "empty tier",
				setTier: "",
				wantErr: "execution tier must be one of",
			},
			{
				name:    "unknown tier",
				setTier: "docker",
				wantErr: "execution tier must be one of",
			},
			{
				name:    "capitalized tier",
				setTier: "Wasm",
				wantErr: "execution tier must be one of",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := validManifest()
				m.Execution.Tier = tt.setTier
				err := (&m).Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("error message prefix", func(t *testing.T) {
		m := validManifest()
		m.Name = ""
		err := (&m).Validate()
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "manifest validation:"),
			"error should have 'manifest validation:' prefix, got: %s", err.Error())
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultValues(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:18789", cfg.Networking.Listen)
	assert.Equal(t, "local", cfg.Networking.Mode)
	assert.Equal(t, "sqlite", cfg.Storage.Backend)
	assert.Equal(t, 20, cfg.Sessions.Memory.ActiveWindow)
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sigil.yaml")

	content := `
networking:
  listen: "0.0.0.0:9999"
models:
  default: "openai/gpt-4.1"
`
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9999", cfg.Networking.Listen)
	assert.Equal(t, "openai/gpt-4.1", cfg.Models.Default)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("SIGIL_NETWORKING_LISTEN", "10.0.0.1:8080")

	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:8080", cfg.Networking.Listen)
}

func TestValidate_MissingProvider(t *testing.T) {
	cfg := &config.Config{
		Models: config.ModelsConfig{
			Default: "anthropic/claude-sonnet-4-5",
		},
		Providers: map[string]config.ProviderConfig{},
	}

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

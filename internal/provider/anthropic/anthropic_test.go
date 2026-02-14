// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package anthropic_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/anthropic"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface satisfaction check.
var _ provider.Provider = (*anthropic.Provider)(nil)

func TestAnthropicProvider_ImplementsInterface(t *testing.T) {
	// Compile-time check above ensures *anthropic.Provider satisfies provider.Provider.
	// This test serves as an explicit verification point.
	var p provider.Provider = mustNewProvider(t)
	assert.NotNil(t, p)
}

func TestAnthropicProvider_Name(t *testing.T) {
	p := mustNewProvider(t)
	assert.Equal(t, "anthropic", p.Name())
}

func TestAnthropicProvider_ListModels(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	models, err := p.ListModels(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, models)

	// Build a set of model IDs for lookup.
	ids := make(map[string]provider.ModelInfo, len(models))
	for _, m := range models {
		ids[m.ID] = m
	}

	t.Run("includes claude-opus-4-6", func(t *testing.T) {
		m, ok := ids["claude-opus-4-6"]
		require.True(t, ok, "models should include claude-opus-4-6")
		assert.Equal(t, "anthropic", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsVision)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.True(t, m.Capabilities.SupportsThinking)
		assert.Greater(t, m.Capabilities.MaxContextTokens, 0)
		assert.Greater(t, m.Capabilities.MaxOutputTokens, 0)
	})

	t.Run("includes claude-sonnet-4-5", func(t *testing.T) {
		m, ok := ids["claude-sonnet-4-5"]
		require.True(t, ok, "models should include claude-sonnet-4-5")
		assert.Equal(t, "anthropic", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
	})

	t.Run("all models have provider set", func(t *testing.T) {
		for _, m := range models {
			assert.Equal(t, "anthropic", m.Provider, "model %s should have provider=anthropic", m.ID)
			assert.NotEmpty(t, m.Name, "model %s should have a display name", m.ID)
		}
	})
}

func TestAnthropicProvider_MissingAPIKey(t *testing.T) {
	_, err := anthropic.New(anthropic.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
	assert.True(t, sigilerr.IsInvalidInput(err), "missing API key should be CodeProviderRequestInvalid")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderRequestInvalid))
}

func TestAnthropicProvider_Status(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", status.Provider)
	assert.True(t, status.Available)
}

func TestAnthropicProvider_Available(t *testing.T) {
	p := mustNewProvider(t)
	assert.True(t, p.Available(context.Background()))
}

func TestAnthropicProvider_Close(t *testing.T) {
	p := mustNewProvider(t)
	assert.NoError(t, p.Close())
}

// mustNewProvider creates a provider with a dummy API key for unit tests.
func mustNewProvider(t *testing.T) *anthropic.Provider {
	t.Helper()
	p, err := anthropic.New(anthropic.Config{
		APIKey: "test-key-not-real",
	})
	require.NoError(t, err)
	return p
}

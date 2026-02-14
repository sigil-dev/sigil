// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openrouter_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/openrouter"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface satisfaction check.
var _ provider.Provider = (*openrouter.Provider)(nil)

func TestOpenRouterProvider_ImplementsInterface(t *testing.T) {
	// Compile-time check above ensures *openrouter.Provider satisfies provider.Provider.
	// This test serves as an explicit verification point.
	var p provider.Provider = mustNewProvider(t)
	assert.NotNil(t, p)
}

func TestOpenRouterProvider_Name(t *testing.T) {
	p := mustNewProvider(t)
	assert.Equal(t, "openrouter", p.Name())
}

func TestOpenRouterProvider_ListModels(t *testing.T) {
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

	t.Run("includes anthropic/claude-sonnet-4-5", func(t *testing.T) {
		m, ok := ids["anthropic/claude-sonnet-4-5"]
		require.True(t, ok, "models should include anthropic/claude-sonnet-4-5")
		assert.Equal(t, "openrouter", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.Greater(t, m.Capabilities.MaxContextTokens, 0)
	})

	t.Run("includes openai/gpt-4.1", func(t *testing.T) {
		m, ok := ids["openai/gpt-4.1"]
		require.True(t, ok, "models should include openai/gpt-4.1")
		assert.Equal(t, "openrouter", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
	})

	t.Run("includes google/gemini-2.5-pro", func(t *testing.T) {
		m, ok := ids["google/gemini-2.5-pro"]
		require.True(t, ok, "models should include google/gemini-2.5-pro")
		assert.Equal(t, "openrouter", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.Greater(t, m.Capabilities.MaxContextTokens, 0)
	})

	t.Run("includes meta-llama/llama-4-maverick", func(t *testing.T) {
		m, ok := ids["meta-llama/llama-4-maverick"]
		require.True(t, ok, "models should include meta-llama/llama-4-maverick")
		assert.Equal(t, "openrouter", m.Provider)
		assert.True(t, m.Capabilities.SupportsStreaming)
	})

	t.Run("all models have provider set", func(t *testing.T) {
		for _, m := range models {
			assert.Equal(t, "openrouter", m.Provider, "model %s should have provider=openrouter", m.ID)
			assert.NotEmpty(t, m.Name, "model %s should have a display name", m.ID)
		}
	})
}

func TestOpenRouterProvider_MissingAPIKey(t *testing.T) {
	_, err := openrouter.New(openrouter.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
	assert.True(t, sigilerr.IsInvalidInput(err), "missing API key should be CodeProviderRequestInvalid")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderRequestInvalid))
}

func TestOpenRouterProvider_Status(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "openrouter", status.Provider)
	assert.True(t, status.Available)
}

func TestOpenRouterProvider_Available(t *testing.T) {
	p := mustNewProvider(t)
	assert.True(t, p.Available(context.Background()))
}

func TestOpenRouterProvider_Close(t *testing.T) {
	p := mustNewProvider(t)
	assert.NoError(t, p.Close())
}

// mustNewProvider creates a provider with a dummy API key for unit tests.
func mustNewProvider(t *testing.T) *openrouter.Provider {
	t.Helper()
	p, err := openrouter.New(openrouter.Config{
		APIKey: "test-key-not-real",
	})
	require.NoError(t, err)
	return p
}

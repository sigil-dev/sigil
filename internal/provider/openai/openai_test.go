// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openai_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface satisfaction check.
var _ provider.Provider = (*openai.Provider)(nil)

func TestOpenAIProvider_ImplementsInterface(t *testing.T) {
	// Compile-time check above ensures *openai.Provider satisfies provider.Provider.
	// This test serves as an explicit verification point.
	var p provider.Provider = mustNewProvider(t)
	assert.NotNil(t, p)
}

func TestOpenAIProvider_Name(t *testing.T) {
	p := mustNewProvider(t)
	assert.Equal(t, "openai", p.Name())
}

func TestOpenAIProvider_ListModels(t *testing.T) {
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

	t.Run("includes gpt-4.1", func(t *testing.T) {
		m, ok := ids["gpt-4.1"]
		require.True(t, ok, "models should include gpt-4.1")
		assert.Equal(t, "openai", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsVision)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.Greater(t, m.Capabilities.MaxContextTokens, 0)
	})

	t.Run("includes gpt-4.1-mini", func(t *testing.T) {
		m, ok := ids["gpt-4.1-mini"]
		require.True(t, ok, "models should include gpt-4.1-mini")
		assert.Equal(t, "openai", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
	})

	t.Run("all models have provider set", func(t *testing.T) {
		for _, m := range models {
			assert.Equal(t, "openai", m.Provider, "model %s should have provider=openai", m.ID)
			assert.NotEmpty(t, m.Name, "model %s should have a display name", m.ID)
		}
	})
}

func TestOpenAIProvider_MissingAPIKey(t *testing.T) {
	_, err := openai.New(openai.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestOpenAIProvider_Status(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "openai", status.Provider)
	assert.True(t, status.Available)
}

func TestOpenAIProvider_Available(t *testing.T) {
	p := mustNewProvider(t)
	assert.True(t, p.Available(context.Background()))
}

func TestOpenAIProvider_Close(t *testing.T) {
	p := mustNewProvider(t)
	assert.NoError(t, p.Close())
}

// mustNewProvider creates a provider with a dummy API key for unit tests.
func mustNewProvider(t *testing.T) *openai.Provider {
	t.Helper()
	p, err := openai.New(openai.Config{
		APIKey: "test-key-not-real",
	})
	require.NoError(t, err)
	return p
}

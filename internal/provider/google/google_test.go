// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package google_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/google"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface satisfaction check.
var _ provider.Provider = (*google.Provider)(nil)

func TestGoogleProvider_ImplementsInterface(t *testing.T) {
	// Compile-time check above ensures *google.Provider satisfies provider.Provider.
	// This test serves as an explicit verification point.
	var p provider.Provider = mustNewProvider(t)
	assert.NotNil(t, p)
}

func TestGoogleProvider_Name(t *testing.T) {
	p := mustNewProvider(t)
	assert.Equal(t, "google", p.Name())
}

func TestGoogleProvider_ListModels(t *testing.T) {
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

	t.Run("includes gemini-2.5-pro", func(t *testing.T) {
		m, ok := ids["gemini-2.5-pro"]
		require.True(t, ok, "models should include gemini-2.5-pro")
		assert.Equal(t, "google", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsVision)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.True(t, m.Capabilities.SupportsThinking)
		assert.Greater(t, m.Capabilities.MaxContextTokens, 0)
		assert.Greater(t, m.Capabilities.MaxOutputTokens, 0)
	})

	t.Run("includes gemini-2.5-flash", func(t *testing.T) {
		m, ok := ids["gemini-2.5-flash"]
		require.True(t, ok, "models should include gemini-2.5-flash")
		assert.Equal(t, "google", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.True(t, m.Capabilities.SupportsThinking)
	})

	t.Run("includes gemini-2.0-flash", func(t *testing.T) {
		m, ok := ids["gemini-2.0-flash"]
		require.True(t, ok, "models should include gemini-2.0-flash")
		assert.Equal(t, "google", m.Provider)
		assert.True(t, m.Capabilities.SupportsTools)
		assert.True(t, m.Capabilities.SupportsStreaming)
		assert.False(t, m.Capabilities.SupportsThinking)
	})

	t.Run("all models have provider set", func(t *testing.T) {
		for _, m := range models {
			assert.Equal(t, "google", m.Provider, "model %s should have provider=google", m.ID)
			assert.NotEmpty(t, m.Name, "model %s should have a display name", m.ID)
		}
	})
}

func TestGoogleProvider_MissingAPIKey(t *testing.T) {
	_, err := google.New(google.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestGoogleProvider_Status(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "google", status.Provider)
	assert.True(t, status.Available)
}

func TestGoogleProvider_Available(t *testing.T) {
	p := mustNewProvider(t)
	assert.True(t, p.Available(context.Background()))
}

func TestGoogleProvider_Close(t *testing.T) {
	p := mustNewProvider(t)
	assert.NoError(t, p.Close())
}

// mustNewProvider creates a provider with a dummy API key for unit tests.
func mustNewProvider(t *testing.T) *google.Provider {
	t.Helper()
	p, err := google.New(google.Config{
		APIKey: "test-key-not-real",
	})
	require.NoError(t, err)
	return p
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package google_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/google"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
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
	assert.True(t, sigilerr.IsInvalidInput(err), "missing API key should be CodeProviderRequestInvalid")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderRequestInvalid))
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

// TestConvertMessages_OriginTagging verifies that origin tags are prepended to
// message content at the provider conversion layer when OriginTagging is enabled.
func TestConvertMessages_OriginTagging(t *testing.T) {
	tests := []struct {
		name          string
		msgs          []provider.Message
		originTagging bool
		// wantPrefixes maps result index → expected content check.
		wantLen      int
		wantContents map[int]string
		// wantFuncResponse maps result index → expected function response "result" value.
		wantFuncResponse map[int]string
	}{
		{
			name: "user message with origin tagging enabled gets [user_input] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: types.OriginUserInput},
			},
			originTagging: true,
			wantLen:       1,
			wantContents:  map[int]string{0: "[user_input] hello world"},
		},
		{
			name: "user message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: types.OriginUserInput},
			},
			originTagging: false,
			wantLen:       1,
			wantContents:  map[int]string{0: "hello world"},
		},
		{
			name: "tool message with origin tagging enabled gets [tool_output] prefix in function response",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolName: "my_tool"},
			},
			originTagging:    true,
			wantLen:          1,
			wantFuncResponse: map[int]string{0: "[tool_output] result data"},
		},
		{
			name: "tool message with origin tagging disabled has no prefix in function response",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolName: "my_tool"},
			},
			originTagging:    false,
			wantLen:          1,
			wantFuncResponse: map[int]string{0: "result data"},
		},
		{
			name: "assistant message never gets origin tag even when tagging enabled",
			msgs: []provider.Message{
				{Role: store.MessageRoleAssistant, Content: "I can help"},
			},
			originTagging: true,
			wantLen:       1,
			wantContents:  map[int]string{0: "I can help"},
		},
		{
			name: "mixed conversation with origin tagging applies tags only to user and tool",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "question", Origin: types.OriginUserInput},
				{Role: store.MessageRoleAssistant, Content: "answer"},
				{Role: store.MessageRoleTool, Content: "tool result", Origin: types.OriginToolOutput, ToolName: "my_tool"},
			},
			originTagging:    true,
			wantLen:          3,
			wantContents:     map[int]string{0: "[user_input] question", 1: "answer"},
			wantFuncResponse: map[int]string{2: "[tool_output] tool result"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, err := google.ConvertMessages(tt.msgs, tt.originTagging)
			require.NoError(t, err)
			require.Len(t, contents, tt.wantLen, "result count mismatch")

			for idx, wantText := range tt.wantContents {
				c := contents[idx]
				require.NotEmpty(t, c.Parts, "content at index %d has no parts", idx)
				assert.Equal(t, wantText, c.Parts[0].Text,
					"content[%d] text mismatch", idx)
			}

			for idx, wantResult := range tt.wantFuncResponse {
				c := contents[idx]
				require.NotEmpty(t, c.Parts, "content at index %d has no parts", idx)
				fr := c.Parts[0].FunctionResponse
				require.NotNil(t, fr, "content[%d] expected FunctionResponse part", idx)
				gotResult, ok := fr.Response["result"]
				require.True(t, ok, "content[%d] FunctionResponse missing 'result' key", idx)
				assert.Equal(t, wantResult, gotResult,
					"content[%d] FunctionResponse result mismatch", idx)
			}
		})
	}
}

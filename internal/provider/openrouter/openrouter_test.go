// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openrouter_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/openrouter"
	"github.com/sigil-dev/sigil/internal/store"
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

// TestConvertMessages_OriginTagging verifies that origin tags are prepended to
// message content at the provider conversion layer when OriginTagging is enabled.
func TestConvertMessages_OriginTagging(t *testing.T) {
	tests := []struct {
		name          string
		msgs          []provider.Message
		systemPrompt  string
		originTagging bool
		// wantLen is the expected number of result messages.
		wantLen int
		// wantContents maps result index → expected content string.
		wantContents map[int]string
	}{
		{
			name: "user message with origin tagging enabled gets [user_input] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: provider.OriginUser},
			},
			originTagging: true,
			wantLen:       1,
			wantContents:  map[int]string{0: "[user_input] hello world"},
		},
		{
			name: "user message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: provider.OriginUser},
			},
			originTagging: false,
			wantLen:       1,
			wantContents:  map[int]string{0: "hello world"},
		},
		{
			name: "tool message with origin tagging enabled gets [tool_output] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: provider.OriginTool, ToolCallID: "call-1"},
			},
			originTagging: true,
			wantLen:       1,
			wantContents:  map[int]string{0: "[tool_output] result data"},
		},
		{
			name: "tool message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: provider.OriginTool, ToolCallID: "call-1"},
			},
			originTagging: false,
			wantLen:       1,
			wantContents:  map[int]string{0: "result data"},
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
				{Role: store.MessageRoleUser, Content: "question", Origin: provider.OriginUser},
				{Role: store.MessageRoleAssistant, Content: "answer"},
				{Role: store.MessageRoleTool, Content: "tool result", Origin: provider.OriginTool, ToolCallID: "call-2"},
			},
			originTagging: true,
			wantLen:       3,
			wantContents: map[int]string{
				0: "[user_input] question",
				1: "answer",
				2: "[tool_output] tool result",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := openrouter.ConvertMessages(tt.msgs, tt.systemPrompt, tt.originTagging)
			require.NoError(t, err)
			require.Len(t, params, tt.wantLen, "result count mismatch")

			for idx, wantContent := range tt.wantContents {
				msg := params[idx]
				switch {
				case msg.OfUser != nil:
					assert.Equal(t, wantContent, msg.OfUser.Content.OfString.Value,
						"message[%d] user content mismatch", idx)
				case msg.OfAssistant != nil:
					assert.Equal(t, wantContent, msg.OfAssistant.Content.OfString.Value,
						"message[%d] assistant content mismatch", idx)
				case msg.OfTool != nil:
					assert.Equal(t, wantContent, msg.OfTool.Content.OfString.Value,
						"message[%d] tool content mismatch", idx)
				default:
					t.Errorf("message[%d] has unexpected type (not user, assistant, or tool)", idx)
				}
			}
		})
	}
}

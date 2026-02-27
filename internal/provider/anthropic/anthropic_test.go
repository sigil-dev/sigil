// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package anthropic_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/anthropic"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
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
	require.NotNil(t, status.Health)
	assert.True(t, status.Health.Available)
	assert.Equal(t, int64(0), status.Health.FailureCount)
	assert.Nil(t, status.Health.LastFailureAt)
	assert.Nil(t, status.Health.CooldownUntil)
}

func TestAnthropicProvider_Status_AfterFailure(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	p.RecordFailure()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", status.Provider)
	assert.False(t, status.Available)
	assert.Contains(t, status.Message, "cooldown")
	require.NotNil(t, status.Health)
	assert.False(t, status.Health.Available)
	assert.Equal(t, int64(1), status.Health.FailureCount)
	assert.NotNil(t, status.Health.CooldownUntil)
	assert.NotNil(t, status.Health.LastFailureAt)
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

// TestBuildParams_OriginTagging verifies that OriginTagging in ChatOptions is
// threaded through buildParams — the function Chat() delegates to — so that
// the Anthropic SDK MessageNewParams carries tagged or untagged content.
func TestBuildParams_OriginTagging(t *testing.T) {
	tests := []struct {
		name          string
		originTagging bool
		wantContent   string
	}{
		{
			name:          "tagging enabled: user message content is prefixed with origin tag",
			originTagging: true,
			wantContent:   "[user_input] hello",
		},
		{
			name:          "tagging disabled: user message content has no origin tag prefix",
			originTagging: false,
			wantContent:   "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := provider.ChatRequest{
				Model: "claude-opus-4-6",
				Messages: []provider.Message{
					{Role: store.MessageRoleUser, Content: "hello", Origin: types.OriginUserInput},
				},
				Options: provider.ChatOptions{
					OriginTagging: tt.originTagging,
				},
			}

			params, err := anthropic.BuildParams(req)
			require.NoError(t, err)
			require.Len(t, params.Messages, 1, "expected one message in params")

			msg := params.Messages[0]
			require.NotEmpty(t, msg.Content, "message content should not be empty")
			block := msg.Content[0]
			require.NotNil(t, block.OfText, "expected text block")
			assert.Equal(t, tt.wantContent, block.OfText.Text,
				"buildParams message content mismatch with OriginTagging=%v", tt.originTagging)
		})
	}
}

// TestConvertMessages_OriginTagging verifies that origin tags are prepended to
// message content at the provider conversion layer when OriginTagging is enabled.
func TestConvertMessages_OriginTagging(t *testing.T) {
	tests := []struct {
		name          string
		msgs          []provider.Message
		originTagging bool
		// wantPrefixes maps result index → expected content prefix.
		wantPrefixes map[int]string
	}{
		{
			name: "user message with origin tagging enabled gets [user_input] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: types.OriginUserInput},
			},
			originTagging: true,
			wantPrefixes:  map[int]string{0: "[user_input] hello world"},
		},
		{
			name: "user message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "hello world", Origin: types.OriginUserInput},
			},
			originTagging: false,
			wantPrefixes:  map[int]string{0: "hello world"},
		},
		{
			name: "tool message with origin tagging enabled gets [tool_output] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolCallID: "call-1"},
			},
			originTagging: true,
			wantPrefixes:  map[int]string{0: "[tool_output] result data"},
		},
		{
			name: "tool message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolCallID: "call-1"},
			},
			originTagging: false,
			wantPrefixes:  map[int]string{0: "result data"},
		},
		{
			name: "assistant message never gets origin tag even when tagging enabled",
			msgs: []provider.Message{
				{Role: store.MessageRoleAssistant, Content: "I can help"},
			},
			originTagging: true,
			wantPrefixes:  map[int]string{0: "I can help"},
		},
		{
			name: "system messages are skipped (not emitted as MessageParam)",
			msgs: []provider.Message{
				{Role: store.MessageRoleSystem, Content: "You are a helpful assistant"},
				{Role: store.MessageRoleUser, Content: "hello", Origin: types.OriginUserInput},
			},
			originTagging: true,
			// Only one result (the user message); system is excluded.
			wantPrefixes: map[int]string{0: "[user_input] hello"},
		},
		{
			name: "mixed conversation with origin tagging applies tags only to user and tool",
			msgs: []provider.Message{
				{Role: store.MessageRoleUser, Content: "question", Origin: types.OriginUserInput},
				{Role: store.MessageRoleAssistant, Content: "answer"},
				{Role: store.MessageRoleTool, Content: "tool result", Origin: types.OriginToolOutput, ToolCallID: "call-2"},
			},
			originTagging: true,
			wantPrefixes: map[int]string{
				0: "[user_input] question",
				1: "answer",
				2: "[tool_output] tool result",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := anthropic.ConvertMessages(tt.msgs, tt.originTagging)
			require.NoError(t, err)
			require.Len(t, params, len(tt.wantPrefixes), "result count mismatch")

			for idx, wantContent := range tt.wantPrefixes {
				msg := params[idx]
				require.NotEmpty(t, msg.Content, "message at index %d has no content blocks", idx)

				block := msg.Content[0]
				switch {
				case block.OfText != nil:
					assert.Equal(t, wantContent, block.OfText.Text,
						"message[%d] text content mismatch", idx)
				case block.OfToolResult != nil:
					require.NotEmpty(t, block.OfToolResult.Content, "tool result at index %d has no content", idx)
					textContent := block.OfToolResult.Content[0]
					require.NotNil(t, textContent.OfText, "tool result content at index %d is not a text block", idx)
					assert.Equal(t, wantContent, textContent.OfText.Text,
						"tool result[%d] text content mismatch", idx)
				default:
					t.Errorf("message[%d] has unexpected content block type (neither text nor tool result)", idx)
				}
			}
		})
	}
}

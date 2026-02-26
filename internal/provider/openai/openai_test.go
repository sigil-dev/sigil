// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openai_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/openai"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
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
	assert.True(t, sigilerr.IsInvalidInput(err), "missing API key should be CodeProviderRequestInvalid")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderRequestInvalid))
}

func TestOpenAIProvider_Status(t *testing.T) {
	p := mustNewProvider(t)
	ctx := context.Background()

	status, err := p.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, "openai", status.Provider)
	assert.True(t, status.Available)
	require.NotNil(t, status.Health)
	assert.True(t, status.Health.Available)
	assert.Equal(t, int64(0), status.Health.FailureCount)
	assert.Nil(t, status.Health.LastFailureAt)
	assert.Nil(t, status.Health.CooldownUntil)
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

// TestBuildParams_OriginTagging verifies that OriginTagging in ChatOptions is
// threaded through buildParams — the function Chat() delegates to — so that
// the OpenAI SDK ChatCompletionNewParams carries tagged or untagged content.
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
				Model: "gpt-4.1",
				Messages: []provider.Message{
					{Role: store.MessageRoleUser, Content: "hello", Origin: types.OriginUserInput},
				},
				Options: provider.ChatOptions{
					OriginTagging: tt.originTagging,
				},
			}

			params, err := openai.BuildParams(req)
			require.NoError(t, err)
			require.Len(t, params.Messages, 1, "expected one message in params")

			msg := params.Messages[0]
			require.NotNil(t, msg.OfUser, "expected user message")
			assert.Equal(t, tt.wantContent, msg.OfUser.Content.OfString.Value,
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
			name: "tool message with origin tagging enabled gets [tool_output] prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolCallID: "call-1"},
			},
			originTagging: true,
			wantLen:       1,
			wantContents:  map[int]string{0: "[tool_output] result data"},
		},
		{
			name: "tool message with origin tagging disabled has no prefix",
			msgs: []provider.Message{
				{Role: store.MessageRoleTool, Content: "result data", Origin: types.OriginToolOutput, ToolCallID: "call-1"},
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
				{Role: store.MessageRoleUser, Content: "question", Origin: types.OriginUserInput},
				{Role: store.MessageRoleAssistant, Content: "answer"},
				{Role: store.MessageRoleTool, Content: "tool result", Origin: types.OriginToolOutput, ToolCallID: "call-2"},
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
			params, err := openai.ConvertMessages(tt.msgs, tt.systemPrompt, tt.originTagging)
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

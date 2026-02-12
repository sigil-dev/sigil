// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openai

import (
	"context"
	"encoding/json"
	"fmt"

	openaisdk "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/store"
)

// Config holds OpenAI provider configuration.
type Config struct {
	APIKey  string
	BaseURL string // optional, useful for testing against a mock server
}

// Provider implements provider.Provider using the OpenAI Chat Completions API.
type Provider struct {
	client openaisdk.Client
	config Config
}

// New creates a new OpenAI provider. Returns an error if the API key is missing.
func New(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai: missing api_key in config")
	}

	opts := []option.RequestOption{
		option.WithAPIKey(cfg.APIKey),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	client := openaisdk.NewClient(opts...)
	return &Provider{client: client, config: cfg}, nil
}

func (p *Provider) Name() string { return "openai" }

func (p *Provider) Available(_ context.Context) bool {
	return true
}

// knownModels returns the hardcoded set of known OpenAI models.
func knownModels() []provider.ModelInfo {
	return []provider.ModelInfo{
		{
			ID:       "gpt-4.1",
			Name:     "GPT-4.1",
			Provider: "openai",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsVision:   true,
				SupportsStreaming: true,
				MaxContextTokens: 128000,
				MaxOutputTokens:  32768,
			},
		},
		{
			ID:       "gpt-4.1-mini",
			Name:     "GPT-4.1 Mini",
			Provider: "openai",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsVision:   true,
				SupportsStreaming: true,
				MaxContextTokens: 128000,
				MaxOutputTokens:  16384,
			},
		},
		{
			ID:       "gpt-4.1-nano",
			Name:     "GPT-4.1 Nano",
			Provider: "openai",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsStreaming: true,
				MaxContextTokens: 128000,
				MaxOutputTokens:  16384,
			},
		},
		{
			ID:       "o3",
			Name:     "o3",
			Provider: "openai",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsStreaming: true,
				SupportsThinking: true,
				MaxContextTokens: 200000,
				MaxOutputTokens:  100000,
			},
		},
		{
			ID:       "o4-mini",
			Name:     "o4-mini",
			Provider: "openai",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsStreaming: true,
				SupportsThinking: true,
				MaxContextTokens: 200000,
				MaxOutputTokens:  100000,
			},
		},
	}
}

func (p *Provider) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return knownModels(), nil
}

func (p *Provider) Chat(ctx context.Context, req provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	params, err := buildParams(req)
	if err != nil {
		return nil, fmt.Errorf("openai: building request params: %w", err)
	}

	eventCh := make(chan provider.ChatEvent, 100)

	go func() {
		defer close(eventCh)
		p.streamChat(ctx, params, eventCh)
	}()

	return eventCh, nil
}

func (p *Provider) Status(ctx context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{
		Available: p.Available(ctx),
		Provider:  "openai",
		Message:   "ok",
	}, nil
}

func (p *Provider) Close() error { return nil }

// buildParams converts a provider.ChatRequest into OpenAI SDK ChatCompletionNewParams.
func buildParams(req provider.ChatRequest) (openaisdk.ChatCompletionNewParams, error) {
	msgs, err := convertMessages(req.Messages, req.SystemPrompt)
	if err != nil {
		return openaisdk.ChatCompletionNewParams{}, err
	}

	params := openaisdk.ChatCompletionNewParams{
		Model:    shared.ChatModel(req.Model),
		Messages: msgs,
		StreamOptions: openaisdk.ChatCompletionStreamOptionsParam{
			IncludeUsage: param.NewOpt(true),
		},
	}

	if req.Options.MaxTokens > 0 {
		params.MaxCompletionTokens = param.NewOpt(int64(req.Options.MaxTokens))
	}

	if req.Options.Temperature > 0 {
		params.Temperature = param.NewOpt(float64(req.Options.Temperature))
	}

	if len(req.Options.StopSequences) > 0 {
		params.Stop = openaisdk.ChatCompletionNewParamsStopUnion{
			OfStringArray: req.Options.StopSequences,
		}
	}

	if len(req.Tools) > 0 {
		params.Tools = convertTools(req.Tools)
	}

	return params, nil
}

// convertMessages transforms provider.Message slices into OpenAI SDK message param slices.
// The system prompt is prepended as a system message if present.
func convertMessages(msgs []provider.Message, systemPrompt string) ([]openaisdk.ChatCompletionMessageParamUnion, error) {
	var result []openaisdk.ChatCompletionMessageParamUnion

	if systemPrompt != "" {
		result = append(result, openaisdk.SystemMessage(systemPrompt))
	}

	for _, msg := range msgs {
		switch msg.Role {
		case store.MessageRoleUser:
			result = append(result, openaisdk.UserMessage(msg.Content))
		case store.MessageRoleAssistant:
			result = append(result, openaisdk.AssistantMessage(msg.Content))
		case store.MessageRoleTool:
			result = append(result, openaisdk.ToolMessage(msg.Content, msg.ToolCallID))
		case store.MessageRoleSystem:
			result = append(result, openaisdk.SystemMessage(msg.Content))
		default:
			return nil, fmt.Errorf("openai: unsupported message role %q", msg.Role)
		}
	}

	return result, nil
}

// convertTools transforms provider.ToolDefinition slices into OpenAI SDK tool params.
func convertTools(tools []provider.ToolDefinition) []openaisdk.ChatCompletionToolParam {
	result := make([]openaisdk.ChatCompletionToolParam, 0, len(tools))
	for _, t := range tools {
		result = append(result, openaisdk.ChatCompletionToolParam{
			Function: shared.FunctionDefinitionParam{
				Name:        t.Name,
				Description: param.NewOpt(t.Description),
				Parameters:  shared.FunctionParameters(t.InputSchema),
			},
		})
	}
	return result
}

// streamChat runs the streaming loop, converting SDK events into provider.ChatEvent values.
func (p *Provider) streamChat(ctx context.Context, params openaisdk.ChatCompletionNewParams, ch chan<- provider.ChatEvent) {
	stream := p.client.Chat.Completions.NewStreaming(ctx, params)

	// Track tool call accumulation by index.
	type toolAccum struct {
		id          string
		name        string
		partialArgs string
	}
	toolCalls := make(map[int64]*toolAccum)

	for stream.Next() {
		chunk := stream.Current()

		// Process choices (typically one).
		for _, choice := range chunk.Choices {
			delta := choice.Delta

			// Text content delta.
			if delta.Content != "" {
				ch <- provider.ChatEvent{
					Type: provider.EventTypeTextDelta,
					Text: delta.Content,
				}
			}

			// Tool call deltas.
			for _, tc := range delta.ToolCalls {
				acc, ok := toolCalls[tc.Index]
				if !ok {
					acc = &toolAccum{}
					toolCalls[tc.Index] = acc
				}
				if tc.ID != "" {
					acc.id = tc.ID
				}
				if tc.Function.Name != "" {
					acc.name = tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					acc.partialArgs += tc.Function.Arguments
				}
			}

			// When finish_reason is "tool_calls", emit accumulated tool calls.
			if choice.FinishReason == "tool_calls" {
				for idx, acc := range toolCalls {
					// Validate JSON before sending.
					if !json.Valid([]byte(acc.partialArgs)) {
						acc.partialArgs = "{}"
					}
					ch <- provider.ChatEvent{
						Type: provider.EventTypeToolCall,
						ToolCall: &provider.ToolCall{
							ID:        acc.id,
							Name:      acc.name,
							Arguments: acc.partialArgs,
						},
					}
					delete(toolCalls, idx)
				}
			}
		}

		// Usage chunk (typically last chunk with stream_options.include_usage).
		if chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0 {
			ch <- provider.ChatEvent{
				Type: provider.EventTypeUsage,
				Usage: &provider.Usage{
					InputTokens:    int(chunk.Usage.PromptTokens),
					OutputTokens:   int(chunk.Usage.CompletionTokens),
					CacheReadTokens: int(chunk.Usage.PromptTokensDetails.CachedTokens),
				},
			}
		}
	}

	if err := stream.Err(); err != nil {
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeError,
			Error: err.Error(),
		}
		return
	}

	// Emit any remaining tool calls that weren't flushed by a finish_reason.
	for idx, acc := range toolCalls {
		if !json.Valid([]byte(acc.partialArgs)) {
			acc.partialArgs = "{}"
		}
		ch <- provider.ChatEvent{
			Type: provider.EventTypeToolCall,
			ToolCall: &provider.ToolCall{
				ID:        acc.id,
				Name:      acc.name,
				Arguments: acc.partialArgs,
			},
		}
		delete(toolCalls, idx)
	}

	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
}

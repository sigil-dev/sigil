// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package anthropic

import (
	"context"
	"fmt"

	anthropicsdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/store"
)

// Config holds Anthropic provider configuration.
type Config struct {
	APIKey  string
	BaseURL string // optional, useful for testing against a mock server
}

// Provider implements provider.Provider using the Anthropic Messages API.
type Provider struct {
	client anthropicsdk.Client
	config Config
	health *provider.HealthTracker
}

// New creates a new Anthropic provider. Returns an error if the API key is missing.
func New(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic: missing api_key in config")
	}

	opts := []option.RequestOption{
		option.WithAPIKey(cfg.APIKey),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	client := anthropicsdk.NewClient(opts...)
	return &Provider{
		client: client,
		config: cfg,
		health: provider.NewHealthTracker(provider.DefaultHealthCooldown),
	}, nil
}

func (p *Provider) Name() string { return "anthropic" }

func (p *Provider) Available(_ context.Context) bool {
	return p.health.IsHealthy()
}

func (p *Provider) RecordFailure() { p.health.RecordFailure() }
func (p *Provider) RecordSuccess() { p.health.RecordSuccess() }

// knownModels returns the hardcoded set of known Anthropic models.
func knownModels() []provider.ModelInfo {
	return []provider.ModelInfo{
		{
			ID:       "claude-opus-4-6",
			Name:     "Claude Opus 4.6",
			Provider: "anthropic",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsVision:   true,
				SupportsStreaming: true,
				SupportsThinking: true,
				MaxContextTokens: 200000,
				MaxOutputTokens:  32000,
			},
		},
		{
			ID:       "claude-sonnet-4-5",
			Name:     "Claude Sonnet 4.5",
			Provider: "anthropic",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsVision:   true,
				SupportsStreaming: true,
				SupportsThinking: true,
				MaxContextTokens: 200000,
				MaxOutputTokens:  16000,
			},
		},
		{
			ID:       "claude-haiku-4-5",
			Name:     "Claude Haiku 4.5",
			Provider: "anthropic",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:    true,
				SupportsVision:   true,
				SupportsStreaming: true,
				MaxContextTokens: 200000,
				MaxOutputTokens:  8192,
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
		return nil, fmt.Errorf("anthropic: building request params: %w", err)
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
		Provider:  "anthropic",
		Message:   "ok",
	}, nil
}

func (p *Provider) Close() error { return nil }

// buildParams converts a provider.ChatRequest into Anthropic SDK MessageNewParams.
func buildParams(req provider.ChatRequest) (anthropicsdk.MessageNewParams, error) {
	msgs, err := convertMessages(req.Messages)
	if err != nil {
		return anthropicsdk.MessageNewParams{}, err
	}

	maxTokens := int64(req.Options.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	params := anthropicsdk.MessageNewParams{
		Model:     anthropicsdk.Model(req.Model),
		Messages:  msgs,
		MaxTokens: maxTokens,
	}

	if req.SystemPrompt != "" {
		params.System = []anthropicsdk.TextBlockParam{
			{Text: req.SystemPrompt},
		}
	}

	if req.Options.Temperature != nil {
		params.Temperature = anthropicsdk.Float(float64(*req.Options.Temperature))
	}

	if len(req.Options.StopSequences) > 0 {
		params.StopSequences = req.Options.StopSequences
	}

	if len(req.Tools) > 0 {
		params.Tools = convertTools(req.Tools)
	}

	return params, nil
}

// convertMessages transforms provider.Message slices into Anthropic SDK MessageParam slices.
func convertMessages(msgs []provider.Message) ([]anthropicsdk.MessageParam, error) {
	var result []anthropicsdk.MessageParam

	for _, msg := range msgs {
		switch msg.Role {
		case store.MessageRoleUser:
			result = append(result, anthropicsdk.NewUserMessage(
				anthropicsdk.NewTextBlock(msg.Content),
			))
		case store.MessageRoleAssistant:
			result = append(result, anthropicsdk.NewAssistantMessage(
				anthropicsdk.NewTextBlock(msg.Content),
			))
		case store.MessageRoleTool:
			result = append(result, anthropicsdk.NewUserMessage(
				anthropicsdk.NewToolResultBlock(msg.ToolCallID, msg.Content, false),
			))
		case store.MessageRoleSystem:
			// System messages are handled via the top-level system param,
			// not as individual messages. Skip them here.
			continue
		default:
			return nil, fmt.Errorf("anthropic: unsupported message role %q", msg.Role)
		}
	}

	return result, nil
}

// convertTools transforms provider.ToolDefinition slices into Anthropic SDK tool params.
func convertTools(tools []provider.ToolDefinition) []anthropicsdk.ToolUnionParam {
	result := make([]anthropicsdk.ToolUnionParam, 0, len(tools))
	for _, t := range tools {
		schema := extractSchema(t.InputSchema)
		result = append(result, anthropicsdk.ToolUnionParam{
			OfTool: &anthropicsdk.ToolParam{
				Name:        t.Name,
				Description: anthropicsdk.Opt(t.Description),
				InputSchema: schema,
			},
		})
	}
	return result
}

// extractSchema maps a provider.ToolDefinition.InputSchema (a full JSON Schema
// object with keys like "type", "properties", "required") into the Anthropic SDK's
// ToolInputSchemaParam, which expects Properties and Required as separate fields.
func extractSchema(raw map[string]any) anthropicsdk.ToolInputSchemaParam {
	schema := anthropicsdk.ToolInputSchemaParam{}
	if props, ok := raw["properties"]; ok {
		schema.Properties = props
	}
	if req, ok := raw["required"]; ok {
		if arr, ok := req.([]any); ok {
			strs := make([]string, 0, len(arr))
			for _, v := range arr {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				}
			}
			schema.Required = strs
		}
	}
	return schema
}

// streamChat runs the streaming loop, converting SDK events into provider.ChatEvent values.
func (p *Provider) streamChat(ctx context.Context, params anthropicsdk.MessageNewParams, ch chan<- provider.ChatEvent) {
	stream := p.client.Messages.NewStreaming(ctx, params)

	// Track tool use blocks by index for accumulation.
	type toolAccum struct {
		id          string
		name        string
		partialJSON string
	}
	toolBlocks := make(map[int64]*toolAccum)

	for stream.Next() {
		event := stream.Current()

		switch event.Type {
		case "content_block_start":
			cb := event.ContentBlock
			if cb.Type == "tool_use" {
				toolBlocks[event.Index] = &toolAccum{
					id:   cb.ID,
					name: cb.Name,
				}
			}

		case "content_block_delta":
			delta := event.Delta
			switch delta.Type {
			case "text_delta":
				ch <- provider.ChatEvent{
					Type: provider.EventTypeTextDelta,
					Text: delta.Text,
				}
			case "input_json_delta":
				if acc, ok := toolBlocks[event.Index]; ok {
					acc.partialJSON += delta.PartialJSON
				}
			}

		case "content_block_stop":
			if acc, ok := toolBlocks[event.Index]; ok {
				ch <- provider.ChatEvent{
					Type: provider.EventTypeToolCall,
					ToolCall: &provider.ToolCall{
						ID:        acc.id,
						Name:      acc.name,
						Arguments: acc.partialJSON,
					},
				}
				delete(toolBlocks, event.Index)
			}

		case "message_delta":
			// message_delta carries final usage info
			ch <- provider.ChatEvent{
				Type: provider.EventTypeUsage,
				Usage: &provider.Usage{
					InputTokens:  int(event.Usage.InputTokens),
					OutputTokens: int(event.Usage.OutputTokens),
				},
			}

		case "message_start":
			// Extract initial usage from the message start event.
			if event.Message.Usage.InputTokens > 0 || event.Message.Usage.OutputTokens > 0 {
				ch <- provider.ChatEvent{
					Type: provider.EventTypeUsage,
					Usage: &provider.Usage{
						InputTokens:      int(event.Message.Usage.InputTokens),
						OutputTokens:     int(event.Message.Usage.OutputTokens),
						CacheReadTokens:  int(event.Message.Usage.CacheReadInputTokens),
						CacheWriteTokens: int(event.Message.Usage.CacheCreationInputTokens),
					},
				}
			}

		case "message_stop":
			p.health.RecordSuccess()
			ch <- provider.ChatEvent{Type: provider.EventTypeDone}
			return
		}
	}

	if err := stream.Err(); err != nil {
		p.health.RecordFailure()
		ch <- provider.ChatEvent{
			Type:  provider.EventTypeError,
			Error: err.Error(),
		}
		return
	}

	// If we exit the loop without a message_stop, still send done.
	p.health.RecordSuccess()
	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
}

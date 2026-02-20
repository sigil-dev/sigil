// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/genai"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Config holds Google provider configuration.
type Config struct {
	APIKey string
}

// Provider implements provider.Provider using the Google Gemini API.
type Provider struct {
	client *genai.Client
	config Config
	health *provider.HealthTracker
}

// New creates a new Google provider. Returns an error if the API key is missing.
func New(cfg Config) (*Provider, error) {
	if cfg.APIKey == "" {
		return nil, sigilerr.New(sigilerr.CodeProviderRequestInvalid, "google: missing api_key in config", sigilerr.FieldProvider("google"))
	}

	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  cfg.APIKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeProviderUpstreamFailure, "google: creating client")
	}

	health, err := provider.NewHealthTracker(provider.DefaultHealthCooldown)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeProviderRequestInvalid, "google: creating health tracker")
	}

	return &Provider{
		client: client,
		config: cfg,
		health: health,
	}, nil
}

func (p *Provider) Name() string { return "google" }

func (p *Provider) Available(_ context.Context) bool {
	return p.health.IsHealthy()
}

func (p *Provider) RecordFailure() { p.health.RecordFailure() }
func (p *Provider) RecordSuccess() { p.health.RecordSuccess() }

// knownModels returns the hardcoded set of known Google Gemini models.
func knownModels() []provider.ModelInfo {
	return []provider.ModelInfo{
		{
			ID:       "gemini-2.5-pro",
			Name:     "Gemini 2.5 Pro",
			Provider: "google",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:     true,
				SupportsVision:    true,
				SupportsStreaming: true,
				SupportsThinking:  true,
				MaxContextTokens:  1000000,
				MaxOutputTokens:   65536,
			},
		},
		{
			ID:       "gemini-2.5-flash",
			Name:     "Gemini 2.5 Flash",
			Provider: "google",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:     true,
				SupportsVision:    true,
				SupportsStreaming: true,
				SupportsThinking:  true,
				MaxContextTokens:  1000000,
				MaxOutputTokens:   65536,
			},
		},
		{
			ID:       "gemini-2.0-flash",
			Name:     "Gemini 2.0 Flash",
			Provider: "google",
			Capabilities: provider.ModelCapabilities{
				SupportsTools:     true,
				SupportsVision:    true,
				SupportsStreaming: true,
				MaxContextTokens:  1000000,
				MaxOutputTokens:   8192,
			},
		},
	}
}

func (p *Provider) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return knownModels(), nil
}

func (p *Provider) Chat(ctx context.Context, req provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	contents, err := convertMessages(req.Messages, req.Options.OriginTagging)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeProviderRequestInvalid, "google: converting messages")
	}

	config := buildConfig(req)

	eventCh := make(chan provider.ChatEvent, 100)

	go func() {
		defer close(eventCh)
		p.streamChat(ctx, req.Model, contents, config, eventCh)
	}()

	return eventCh, nil
}

func (p *Provider) Status(ctx context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{
		Available: p.Available(ctx),
		Provider:  "google",
		Message:   "ok",
	}, nil
}

func (p *Provider) Close() error { return nil }

// buildConfig converts a provider.ChatRequest into a genai.GenerateContentConfig.
func buildConfig(req provider.ChatRequest) *genai.GenerateContentConfig {
	cfg := &genai.GenerateContentConfig{}

	if req.Options.Temperature != nil {
		cfg.Temperature = genai.Ptr(*req.Options.Temperature)
	}

	if req.Options.MaxTokens > 0 {
		cfg.MaxOutputTokens = int32(req.Options.MaxTokens)
	}

	if len(req.Options.StopSequences) > 0 {
		cfg.StopSequences = req.Options.StopSequences
	}

	if req.SystemPrompt != "" {
		cfg.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{
				{Text: req.SystemPrompt},
			},
		}
	}

	if len(req.Tools) > 0 {
		cfg.Tools = convertTools(req.Tools)
	}

	return cfg
}

// convertMessages transforms provider.Message slices into genai.Content slices.
// The Google GenAI SDK uses Content with Role and Parts.
// Origin tags are only prepended to user and tool messages (not system or assistant).
// System messages are excluded (handled via SystemInstruction in buildConfig).
// The originTagging flag controls whether tags are prepended at all.
func convertMessages(msgs []provider.Message, originTagging bool) ([]*genai.Content, error) {
	var result []*genai.Content

	for _, msg := range msgs {
		switch msg.Role {
		case store.MessageRoleUser:
			tag := provider.OriginTagIfEnabled(msg.Origin, originTagging)
			result = append(result, &genai.Content{
				Role: "user",
				Parts: []*genai.Part{
					{Text: tag + msg.Content},
				},
			})
		case store.MessageRoleAssistant:
			// Assistant messages are Sigil-generated LLM outputs and MUST NOT have
			// origin tags prepended. Tags are only for untrusted user/tool content.
			result = append(result, &genai.Content{
				Role: "model",
				Parts: []*genai.Part{
					{Text: msg.Content},
				},
			})
		case store.MessageRoleTool:
			tag := provider.OriginTagIfEnabled(msg.Origin, originTagging)
			result = append(result, &genai.Content{
				Role: "user",
				Parts: []*genai.Part{
					{
						FunctionResponse: &genai.FunctionResponse{
							Name:     msg.ToolName,
							Response: map[string]any{"result": tag + msg.Content},
						},
					},
				},
			})
		case store.MessageRoleSystem:
			// System messages are handled via SystemInstruction in config.
			continue
		default:
			return nil, sigilerr.Errorf(sigilerr.CodeProviderRequestInvalid, "google: unsupported message role %q", msg.Role)
		}
	}

	return result, nil
}

// convertTools transforms provider.ToolDefinition slices into genai.Tool slices.
func convertTools(tools []provider.ToolDefinition) []*genai.Tool {
	var decls []*genai.FunctionDeclaration
	for _, t := range tools {
		decls = append(decls, &genai.FunctionDeclaration{
			Name:                 t.Name,
			Description:          t.Description,
			ParametersJsonSchema: t.InputSchema,
		})
	}
	return []*genai.Tool{
		{FunctionDeclarations: decls},
	}
}

// streamChat runs the streaming loop, converting SDK responses into provider.ChatEvent values.
func (p *Provider) streamChat(
	ctx context.Context,
	model string,
	contents []*genai.Content,
	config *genai.GenerateContentConfig,
	ch chan<- provider.ChatEvent,
) {
	for result, err := range p.client.Models.GenerateContentStream(ctx, model, contents, config) {
		if err != nil {
			p.health.RecordFailure()
			ch <- provider.ChatEvent{
				Type:  provider.EventTypeError,
				Error: err.Error(),
			}
			return
		}

		// Process each candidate's parts.
		for _, candidate := range result.Candidates {
			if candidate.Content == nil {
				continue
			}
			for _, part := range candidate.Content.Parts {
				if part.Text != "" {
					ch <- provider.ChatEvent{
						Type: provider.EventTypeTextDelta,
						Text: part.Text,
					}
				}
				if part.FunctionCall != nil {
					args, err := json.Marshal(part.FunctionCall.Args)
					if err != nil {
						p.health.RecordFailure()
						// Log detailed context before returning error event
						argsStr := fmt.Sprintf("%v", part.FunctionCall.Args)
						if len(argsStr) > 200 {
							argsStr = argsStr[:200] + "..."
						}
						slog.Error("failed to marshal tool call arguments",
							"function", part.FunctionCall.Name,
							"args_preview", argsStr,
							"error", err,
						)
						ch <- provider.ChatEvent{
							Type:  provider.EventTypeError,
							Error: sigilerr.Errorf(sigilerr.CodeProviderUpstreamFailure, "google: marshaling tool call arguments for %q: %w", part.FunctionCall.Name, err).Error(),
						}
						return
					}
					ch <- provider.ChatEvent{
						Type: provider.EventTypeToolCall,
						ToolCall: &provider.ToolCall{
							ID:        part.FunctionCall.ID,
							Name:      part.FunctionCall.Name,
							Arguments: string(args),
						},
					}
				}
			}
		}

		// Emit usage from the response if available.
		if result.UsageMetadata != nil {
			ch <- provider.ChatEvent{
				Type: provider.EventTypeUsage,
				Usage: &provider.Usage{
					InputTokens:     int(result.UsageMetadata.PromptTokenCount),
					OutputTokens:    int(result.UsageMetadata.CandidatesTokenCount),
					CacheReadTokens: int(result.UsageMetadata.CachedContentTokenCount),
				},
			}
		}
	}

	p.health.RecordSuccess()
	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
}

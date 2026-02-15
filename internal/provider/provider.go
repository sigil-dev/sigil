// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"

	"github.com/sigil-dev/sigil/internal/store"
)

// Provider is the core interface for LLM providers.
// Built-in providers (Anthropic, OpenAI, Google) are compiled into the gateway.
// Plugin providers implement this via gRPC (defined in api/proto/plugin/v1/provider.proto).
type Provider interface {
	// Name returns the provider's name (e.g., "anthropic", "openai").
	Name() string

	// Available performs a simple boolean liveness check on the provider.
	// Returns true if the provider is reachable and ready to serve requests.
	Available(ctx context.Context) bool

	// ListModels returns available models from this provider.
	ListModels(ctx context.Context) ([]ModelInfo, error)

	// Chat sends a chat request and streams responses.
	Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error)

	// Status returns the provider's current availability and name.
	Status(ctx context.Context) (ProviderStatus, error)

	// Close cleans up provider resources.
	Close() error
}

// Router routes chat requests to the appropriate provider based on model name.
// Implements failover logic, budget checks, and workspace overrides.
type Router interface {
	// Route selects a provider for the given model name.
	// Returns the provider and resolved model ID.
	Route(ctx context.Context, workspaceID, modelName string) (Provider, string, error)

	// RouteWithBudget selects a provider and enforces token budget constraints.
	// Callers should prefer this over Route when budget context is available.
	// The exclude list contains provider names to skip (already-tried providers
	// in the current failover sequence).
	RouteWithBudget(ctx context.Context, workspaceID, modelName string, budget *Budget, exclude []string) (Provider, string, error)

	// RegisterProvider adds a provider to the router.
	RegisterProvider(name string, provider Provider) error

	// MaxAttempts returns the maximum number of provider attempts the router
	// supports (primary + failover candidates). Used by the agent loop to
	// cap its retry count.
	MaxAttempts() int

	// Close shuts down all registered providers.
	Close() error
}

// ChatRequest represents a request to the LLM.
type ChatRequest struct {
	Model        string
	Messages     []Message
	Tools        []ToolDefinition
	SystemPrompt string
	Options      ChatOptions
}

// ChatOptions contains model configuration.
type ChatOptions struct {
	Temperature   *float32
	MaxTokens     int
	StopSequences []string
	Stream        bool
}

// Message represents a conversation message.
type Message struct {
	Role       store.MessageRole
	Content    string
	ToolCallID string
	ToolName   string
}

// ToolDefinition describes a tool available to the agent.
type ToolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ChatEvent is a streaming response event.
type ChatEvent struct {
	Type     EventType
	Text     string
	ToolCall *ToolCall
	Usage    *Usage
	Error    string
}

// EventType defines the type of chat event.
type EventType string

const (
	EventTypeTextDelta EventType = "text_delta"
	EventTypeToolCall  EventType = "tool_call"
	EventTypeUsage     EventType = "usage"
	EventTypeDone      EventType = "done"
	EventTypeError     EventType = "error"
)

// ToolCall represents a tool invocation by the LLM.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string // JSON
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
}

// ModelInfo describes a model's capabilities.
type ModelInfo struct {
	ID           string
	Name         string
	Provider     string
	Capabilities ModelCapabilities
}

// ModelCapabilities declares what a model supports.
type ModelCapabilities struct {
	SupportsTools     bool
	SupportsVision    bool
	SupportsStreaming bool
	SupportsThinking  bool
	MaxContextTokens  int
	MaxOutputTokens   int
}

// ProviderStatus indicates provider health.
type ProviderStatus struct {
	Available bool
	Provider  string
	Message   string
}

// HealthReporter is an optional interface that providers can implement to
// expose circuit-breaker health signals.
//
// Recording responsibilities are split by failure phase:
//   - Pre-stream failures: the agent loop calls RecordFailure when Chat()
//     returns an error (provider unreachable, auth failure, rate limit).
//   - In-stream failures: providers call RecordFailure internally when the
//     event stream encounters errors (malformed response, connection drop).
//   - Success: providers call RecordSuccess internally after a complete,
//     successful stream (agent loop never calls RecordSuccess).
//
// The HealthTracker implements cooldown-based recovery (circuit-breaker
// half-open state), so providers become eligible for retry after the cooldown.
type HealthReporter interface {
	RecordFailure()
	RecordSuccess()
}

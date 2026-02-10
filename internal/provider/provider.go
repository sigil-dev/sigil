// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
)

// Provider is the core interface for LLM providers.
// Built-in providers (Anthropic, OpenAI, Google) are compiled into the gateway.
// Plugin providers implement this via gRPC (defined in api/proto/plugin/v1/provider.proto).
type Provider interface {
	// Name returns the provider's name (e.g., "anthropic", "openai").
	Name() string

	// Available checks if the provider is currently available.
	Available(ctx context.Context) bool

	// ListModels returns available models from this provider.
	ListModels(ctx context.Context) ([]ModelInfo, error)

	// Chat sends a chat request and streams responses.
	Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error)

	// Status checks if the provider is available.
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

	// RegisterProvider adds a provider to the router.
	RegisterProvider(name string, provider Provider) error

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
	Temperature   float32
	MaxTokens     int
	StopSequences []string
	Stream        bool
}

// Message represents a conversation message.
type Message struct {
	Role       MessageRole
	Content    string
	ToolCallID string
	ToolName   string
}

// MessageRole defines the role of a message sender.
type MessageRole string

const (
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleSystem    MessageRole = "system"
	MessageRoleTool      MessageRole = "tool"
)

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

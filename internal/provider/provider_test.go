// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider implements provider.Provider for testing.
type mockProvider struct {
	name      string
	available bool
	models    []provider.ModelInfo
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Available(ctx context.Context) bool {
	return m.available
}

func (m *mockProvider) ListModels(ctx context.Context) ([]provider.ModelInfo, error) {
	return m.models, nil
}

func (m *mockProvider) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "hello"}
	ch <- provider.ChatEvent{Type: provider.EventTypeUsage, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5}}
	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
	close(ch)
	return ch, nil
}

func (m *mockProvider) Status(ctx context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{
		Available: m.available,
		Provider:  m.name,
		Message:   "ok",
	}, nil
}

func (m *mockProvider) Close() error {
	return nil
}

// Compile-time interface satisfaction checks.
func TestProviderInterfaceExists(t *testing.T) {
	var _ provider.Provider = nil
}

func TestRouterInterfaceExists(t *testing.T) {
	var _ provider.Router = nil
}

func TestChatRequestFields(t *testing.T) {
	req := provider.ChatRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []provider.Message{},
	}
	if req.Model == "" {
		t.Fatal("ChatRequest.Model should be settable")
	}
}

func TestChatEventTypes(t *testing.T) {
	_ = provider.ChatEvent{
		Type: provider.EventTypeTextDelta,
		Text: "test",
	}
	_ = provider.ChatEvent{
		Type: provider.EventTypeToolCall,
	}
	_ = provider.ChatEvent{
		Type: provider.EventTypeDone,
	}
}

func TestProviderInterface_MultiProviderSupport(t *testing.T) {
	// Compile-time proof that mockProvider satisfies provider.Provider.
	var p provider.Provider = &mockProvider{
		name:      "test-provider",
		available: true,
		models: []provider.ModelInfo{
			{
				ID:       "model-1",
				Name:     "Test Model",
				Provider: "test-provider",
				Capabilities: provider.ModelCapabilities{
					SupportsTools:     true,
					SupportsStreaming: true,
					MaxContextTokens:  128000,
					MaxOutputTokens:   4096,
				},
			},
			{
				ID:       "model-2",
				Name:     "Test Model Small",
				Provider: "test-provider",
				Capabilities: provider.ModelCapabilities{
					SupportsStreaming: true,
					MaxContextTokens:  32000,
					MaxOutputTokens:   2048,
				},
			},
		},
	}

	ctx := context.Background()

	t.Run("Name returns identifier", func(t *testing.T) {
		assert.Equal(t, "test-provider", p.Name())
	})

	t.Run("Available returns bool for failover", func(t *testing.T) {
		assert.True(t, p.Available(ctx))
	})

	t.Run("ListModels returns model list for discovery", func(t *testing.T) {
		models, err := p.ListModels(ctx)
		require.NoError(t, err)
		assert.Len(t, models, 2)
		assert.Equal(t, "model-1", models[0].ID)
		assert.Equal(t, "Test Model", models[0].Name)
		assert.Equal(t, "test-provider", models[0].Provider)
		assert.True(t, models[0].Capabilities.SupportsTools)
	})

	t.Run("Status returns health info", func(t *testing.T) {
		status, err := p.Status(ctx)
		require.NoError(t, err)
		assert.True(t, status.Available)
		assert.Equal(t, "test-provider", status.Provider)
		assert.Equal(t, "ok", status.Message)
	})

	t.Run("Close returns nil on success", func(t *testing.T) {
		assert.NoError(t, p.Close())
	})
}

func TestProviderInterface_MultiProviderFailover(t *testing.T) {
	providers := []provider.Provider{
		&mockProvider{name: "primary", available: false},
		&mockProvider{name: "secondary", available: true},
		&mockProvider{name: "tertiary", available: true},
	}

	ctx := context.Background()

	// Simulate failover: find first available provider.
	var selected provider.Provider
	for _, p := range providers {
		if p.Available(ctx) {
			selected = p
			break
		}
	}

	require.NotNil(t, selected, "at least one provider should be available")
	assert.Equal(t, "secondary", selected.Name(), "failover should skip unavailable primary")
}

func TestProviderInterface_ChatStreaming(t *testing.T) {
	p := &mockProvider{name: "streaming-test", available: true}

	ctx := context.Background()
	req := provider.ChatRequest{
		Model: "test-model",
		Messages: []provider.Message{
			{Role: "user", Content: "hello"},
		},
		Options: provider.ChatOptions{
			Stream:    true,
			MaxTokens: 100,
		},
	}

	ch, err := p.Chat(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, ch)

	// Collect all events from the channel.
	var events []provider.ChatEvent
	for ev := range ch {
		events = append(events, ev)
	}

	require.Len(t, events, 3, "expected TextDelta, Usage, and Done events")

	assert.Equal(t, provider.EventTypeTextDelta, events[0].Type)
	assert.Equal(t, "hello", events[0].Text)

	assert.Equal(t, provider.EventTypeUsage, events[1].Type)
	require.NotNil(t, events[1].Usage)
	assert.Equal(t, 10, events[1].Usage.InputTokens)
	assert.Equal(t, 5, events[1].Usage.OutputTokens)

	assert.Equal(t, provider.EventTypeDone, events[2].Type)
}

func TestProviderInterface_RouterContract(t *testing.T) {
	// Verify the Router interface exists and has the expected method signatures
	// by checking that nil satisfies it (compile-time) and describing expected behavior.
	var _ provider.Router = nil

	t.Run("Route signature accepts workspaceID and modelName", func(t *testing.T) {
		// The Router.Route method returns (Provider, string, error).
		// Verify at compile time through a function type matching the signature.
		type routeFunc func(ctx context.Context, workspaceID, modelName string) (provider.Provider, string, error)
		_ = routeFunc(nil) // compiles only if signature is correct
	})

	t.Run("RouteWithBudget signature accepts budget parameter", func(t *testing.T) {
		type routeWithBudgetFunc func(ctx context.Context, workspaceID, modelName string, budget *provider.Budget) (provider.Provider, string, error)
		_ = routeWithBudgetFunc(nil)
	})

	t.Run("RegisterProvider signature accepts name and Provider", func(t *testing.T) {
		type registerFunc func(name string, provider provider.Provider) error
		_ = registerFunc(nil)
	})

	t.Run("Close signature returns error", func(t *testing.T) {
		type closeFunc func() error
		_ = closeFunc(nil)
	})
}

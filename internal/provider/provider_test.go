// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
)

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

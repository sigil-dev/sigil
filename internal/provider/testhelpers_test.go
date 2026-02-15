// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"context"

	"github.com/sigil-dev/sigil/internal/provider"
)

// mockProviderBase provides a reusable base implementation of provider.Provider
// for use in tests. Embed this in test-specific mocks and override methods as needed.
type mockProviderBase struct {
	name      string
	available bool
	models    []provider.ModelInfo
}

func newMockProviderBase(name string, available bool) *mockProviderBase {
	return &mockProviderBase{
		name:      name,
		available: available,
		models:    nil,
	}
}

func (m *mockProviderBase) Name() string {
	return m.name
}

func (m *mockProviderBase) Available(ctx context.Context) bool {
	return m.available
}

func (m *mockProviderBase) ListModels(ctx context.Context) ([]provider.ModelInfo, error) {
	return m.models, nil
}

func (m *mockProviderBase) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 3)
	ch <- provider.ChatEvent{Type: provider.EventTypeTextDelta, Text: "hello"}
	ch <- provider.ChatEvent{Type: provider.EventTypeUsage, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5}}
	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
	close(ch)
	return ch, nil
}

func (m *mockProviderBase) Status(ctx context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{
		Available: m.available,
		Provider:  m.name,
		Message:   "ok",
	}, nil
}

func (m *mockProviderBase) Close() error {
	return nil
}

// mockProviderWithHealth extends mockProviderBase with health tracking capabilities.
// It allows tests to simulate provider health state changes during streaming.
type mockProviderWithHealth struct {
	*mockProviderBase
	healthTracker *provider.HealthTracker
	chatFunc      func(context.Context, provider.ChatRequest) (<-chan provider.ChatEvent, error)
}

func (m *mockProviderWithHealth) Chat(ctx context.Context, req provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	if m.chatFunc != nil {
		return m.chatFunc(ctx, req)
	}
	return m.mockProviderBase.Chat(ctx, req)
}

func (m *mockProviderWithHealth) RecordFailure() {
	m.healthTracker.RecordFailure()
}

func (m *mockProviderWithHealth) RecordSuccess() {
	m.healthTracker.RecordSuccess()
}

func (m *mockProviderWithHealth) Available(ctx context.Context) bool {
	return m.healthTracker.IsHealthy()
}

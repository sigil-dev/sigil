// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRegistryProvider implements provider.Provider for registry tests.
type mockRegistryProvider struct {
	name      string
	available bool
}

func (m *mockRegistryProvider) Name() string                     { return m.name }
func (m *mockRegistryProvider) Available(_ context.Context) bool { return m.available }
func (m *mockRegistryProvider) Close() error                     { return nil }

func (m *mockRegistryProvider) ListModels(_ context.Context) ([]provider.ModelInfo, error) {
	return nil, nil
}

func (m *mockRegistryProvider) Chat(_ context.Context, _ provider.ChatRequest) (<-chan provider.ChatEvent, error) {
	ch := make(chan provider.ChatEvent, 1)
	ch <- provider.ChatEvent{Type: provider.EventTypeDone}
	close(ch)
	return ch, nil
}

func (m *mockRegistryProvider) Status(_ context.Context) (provider.ProviderStatus, error) {
	return provider.ProviderStatus{Available: m.available, Provider: m.name}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := provider.NewRegistry()

	p := &mockRegistryProvider{name: "anthropic", available: true}
	reg.Register("anthropic", p)

	got, err := reg.Get("anthropic")
	require.NoError(t, err)
	assert.Equal(t, "anthropic", got.Name())

	_, err = reg.Get("nonexistent")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderNotFound))
}

func TestRegistry_RouteDefault(t *testing.T) {
	reg := provider.NewRegistry()

	anthropic := &mockRegistryProvider{name: "anthropic", available: true}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()
	p, model, err := reg.Route(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
	assert.Equal(t, "claude-sonnet-4-5", model)
}

func TestRegistry_RouteWorkspaceOverride(t *testing.T) {
	reg := provider.NewRegistry()

	anthropic := &mockRegistryProvider{name: "anthropic", available: true}
	openai := &mockRegistryProvider{name: "openai", available: true}
	reg.Register("anthropic", anthropic)
	reg.Register("openai", openai)

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetOverride("homelab", "openai/gpt-4.1")

	ctx := context.Background()

	// Default workspace gets anthropic.
	p, model, err := reg.Route(ctx, "other-workspace", "")
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
	assert.Equal(t, "claude-sonnet-4-5", model)

	// Homelab workspace gets openai.
	p, model, err = reg.Route(ctx, "homelab", "")
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
	assert.Equal(t, "gpt-4.1", model)
}

func TestRegistry_Failover(t *testing.T) {
	reg := provider.NewRegistry()

	anthropic := &mockRegistryProvider{name: "anthropic", available: false}
	openai := &mockRegistryProvider{name: "openai", available: true}
	reg.Register("anthropic", anthropic)
	reg.Register("openai", openai)

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetFailover([]string{"openai/gpt-4.1"})

	ctx := context.Background()
	p, model, err := reg.Route(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
	assert.Equal(t, "gpt-4.1", model)
}

func TestRegistry_AllProvidersDown(t *testing.T) {
	reg := provider.NewRegistry()

	anthropic := &mockRegistryProvider{name: "anthropic", available: false}
	openai := &mockRegistryProvider{name: "openai", available: false}
	reg.Register("anthropic", anthropic)
	reg.Register("openai", openai)

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetFailover([]string{"openai/gpt-4.1"})

	ctx := context.Background()
	_, _, err := reg.Route(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all providers")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderAllUnavailable))
}

func TestRegistry_BudgetEnforcement(t *testing.T) {
	reg := provider.NewRegistry()

	anthropic := &mockRegistryProvider{name: "anthropic", available: true}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()

	// Route with an exceeded budget.
	budget := &provider.Budget{
		MaxSessionTokens:  1000,
		UsedSessionTokens: 1500,
	}
	_, _, err := reg.RouteWithBudget(ctx, "", "", budget)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "budget")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded))
}

func TestRegistry_ImplementsRouter(t *testing.T) {
	// Compile-time check that Registry satisfies Router.
	var _ provider.Router = provider.NewRegistry()
}

func TestRegistry_RegisterProvider(t *testing.T) {
	reg := provider.NewRegistry()
	p := &mockRegistryProvider{name: "test", available: true}

	// RegisterProvider is the Router interface method.
	err := reg.RegisterProvider("test", p)
	require.NoError(t, err)

	got, err := reg.Get("test")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Name())
}

func TestRegistry_Close(t *testing.T) {
	reg := provider.NewRegistry()
	p := &mockRegistryProvider{name: "test", available: true}
	reg.Register("test", p)

	err := reg.Close()
	assert.NoError(t, err)
}

func TestRegistry_MaxAttempts(t *testing.T) {
	reg := provider.NewRegistry()

	// Empty failover chain → 1 attempt (primary only).
	assert.Equal(t, 1, reg.MaxAttempts())

	// Set failover chain with 3 entries → 4 attempts total.
	reg.SetFailover([]string{"a/model", "b/model", "c/model"})
	assert.Equal(t, 4, reg.MaxAttempts())
}

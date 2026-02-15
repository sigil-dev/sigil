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

// mockRegistryProvider embeds mockProviderBase for registry tests.
type mockRegistryProvider struct {
	*mockProviderBase
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := provider.NewRegistry()

	p := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
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

	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
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

	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	openai := &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", true)}
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

	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", false)}
	openai := &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", true)}
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

	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", false)}
	openai := &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", false)}
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

	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()

	// Route with an exceeded budget.
	budget := &provider.Budget{
		MaxSessionTokens:  1000,
		UsedSessionTokens: 1500,
	}
	_, _, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
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
	p := &mockRegistryProvider{mockProviderBase: newMockProviderBase("test", true)}

	// RegisterProvider is the Router interface method.
	err := reg.RegisterProvider("test", p)
	require.NoError(t, err)

	got, err := reg.Get("test")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Name())
}

func TestRegistry_Close(t *testing.T) {
	reg := provider.NewRegistry()
	p := &mockRegistryProvider{mockProviderBase: newMockProviderBase("test", true)}
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

func TestRegistry_BudgetEnforcement_HourlyUSD(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()

	tests := []struct {
		name    string
		budget  *provider.Budget
		wantErr bool
		errCode sigilerr.Code
	}{
		{
			name: "hourly budget not exceeded",
			budget: &provider.Budget{
				MaxHourUSD:  5.00,
				UsedHourUSD: 3.00,
			},
			wantErr: false,
		},
		{
			name: "hourly budget exactly met",
			budget: &provider.Budget{
				MaxHourUSD:  5.00,
				UsedHourUSD: 5.00,
			},
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "hourly budget exceeded",
			budget: &provider.Budget{
				MaxHourUSD:  5.00,
				UsedHourUSD: 7.50,
			},
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "hourly budget zero means unlimited",
			budget: &provider.Budget{
				MaxHourUSD:  0,
				UsedHourUSD: 999.99,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := reg.RouteWithBudget(ctx, "", "", tt.budget, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.errCode))
				assert.Contains(t, err.Error(), "budget")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRegistry_BudgetEnforcement_DailyUSD(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()

	tests := []struct {
		name    string
		budget  *provider.Budget
		wantErr bool
		errCode sigilerr.Code
	}{
		{
			name: "daily budget not exceeded",
			budget: &provider.Budget{
				MaxDayUSD:  50.00,
				UsedDayUSD: 25.00,
			},
			wantErr: false,
		},
		{
			name: "daily budget exactly met",
			budget: &provider.Budget{
				MaxDayUSD:  50.00,
				UsedDayUSD: 50.00,
			},
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "daily budget exceeded",
			budget: &provider.Budget{
				MaxDayUSD:  50.00,
				UsedDayUSD: 75.00,
			},
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "daily budget zero means unlimited",
			budget: &provider.Budget{
				MaxDayUSD:  0,
				UsedDayUSD: 999.99,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := reg.RouteWithBudget(ctx, "", "", tt.budget, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.errCode))
				assert.Contains(t, err.Error(), "budget")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRegistry_BudgetEnforcement_CombinedLimits(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	ctx := context.Background()

	tests := []struct {
		name    string
		budget  *provider.Budget
		wantErr bool
	}{
		{
			name: "all limits within bounds",
			budget: &provider.Budget{
				MaxSessionTokens:  100000,
				UsedSessionTokens: 5000,
				MaxHourUSD:        5.00,
				UsedHourUSD:       1.00,
				MaxDayUSD:         50.00,
				UsedDayUSD:        10.00,
			},
			wantErr: false,
		},
		{
			name: "tokens exceeded but USD ok",
			budget: &provider.Budget{
				MaxSessionTokens:  1000,
				UsedSessionTokens: 1500,
				MaxHourUSD:        5.00,
				UsedHourUSD:       1.00,
				MaxDayUSD:         50.00,
				UsedDayUSD:        10.00,
			},
			wantErr: true,
		},
		{
			name: "hourly exceeded but tokens and daily ok",
			budget: &provider.Budget{
				MaxSessionTokens:  100000,
				UsedSessionTokens: 5000,
				MaxHourUSD:        5.00,
				UsedHourUSD:       6.00,
				MaxDayUSD:         50.00,
				UsedDayUSD:        10.00,
			},
			wantErr: true,
		},
		{
			name: "daily exceeded but tokens and hourly ok",
			budget: &provider.Budget{
				MaxSessionTokens:  100000,
				UsedSessionTokens: 5000,
				MaxHourUSD:        5.00,
				UsedHourUSD:       1.00,
				MaxDayUSD:         50.00,
				UsedDayUSD:        55.00,
			},
			wantErr: true,
		},
		{
			name:    "nil budget always passes",
			budget:  nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := reg.RouteWithBudget(ctx, "", "", tt.budget, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBudget_USDFieldsExist(t *testing.T) {
	b := provider.Budget{
		MaxSessionTokens:  100000,
		UsedSessionTokens: 0,
		MaxHourUSD:        5.00,
		UsedHourUSD:       0,
		MaxDayUSD:         50.00,
		UsedDayUSD:        0,
	}
	assert.Equal(t, 5.00, b.MaxHourUSD)
	assert.Equal(t, 50.00, b.MaxDayUSD)
}

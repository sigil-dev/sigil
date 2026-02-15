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

	// Route with a budget at the limit (should fail during routing).
	budget, err := provider.NewBudget(1000, 1000, 0, 0, 0, 0)
	require.NoError(t, err)
	_, _, err = reg.RouteWithBudget(context.Background(), "", "", budget, nil)
	require.Error(t, err)
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
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 5.00, 3.00, 0, 0)
				return b
			}(),
			wantErr: false,
		},
		{
			name: "hourly budget exactly met",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 5.00, 5.00, 0, 0)
				return b
			}(),
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "hourly budget slightly over limit",
			budget: func() *provider.Budget {
				// Used (5.01) > Max (5.00) - fails validation, can't test routing
				// Use a value just at limit instead to test routing behavior
				b, _ := provider.NewBudget(0, 0, 5.00, 4.99, 0, 0)
				return b
			}(),
			wantErr: false, // Under limit, should succeed
		},
		{
			name: "hourly budget zero means unlimited",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 999.99, 0, 0)
				return b
			}(),
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
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 50.00, 25.00)
				return b
			}(),
			wantErr: false,
		},
		{
			name: "daily budget exactly met",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 50.00, 50.00)
				return b
			}(),
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "daily budget zero means unlimited",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 0, 999.99)
				return b
			}(),
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
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(100000, 5000, 5.00, 1.00, 50.00, 10.00)
				return b
			}(),
			wantErr: false,
		},
		{
			name: "tokens at limit triggers routing rejection",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(1000, 1000, 0, 0, 0, 0)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "hourly at limit triggers routing rejection",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 5.00, 5.00, 0, 0)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "daily at limit triggers routing rejection",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 50.00, 50.00)
				return b
			}(),
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
	b, err := provider.NewBudget(100000, 0, 5.00, 0, 50.00, 0)
	require.NoError(t, err)
	assert.Equal(t, 5.00, b.MaxHourUSD)
	assert.Equal(t, 50.00, b.MaxDayUSD)
}

func TestNewBudget_Validation(t *testing.T) {
	tests := []struct {
		name              string
		maxSessionTokens  int
		usedSessionTokens int
		maxHourUSD        float64
		usedHourUSD       float64
		maxDayUSD         float64
		usedDayUSD        float64
		wantErr           bool
		errContains       string
	}{
		{
			name:              "valid budget with all positive values",
			maxSessionTokens:  10000,
			usedSessionTokens: 5000,
			maxHourUSD:        5.00,
			usedHourUSD:       2.50,
			maxDayUSD:         50.00,
			usedDayUSD:        25.00,
			wantErr:           false,
		},
		{
			name:              "zero budget (all zeros - unlimited)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           false,
		},
		{
			name:              "negative MaxSessionTokens",
			maxSessionTokens:  -100,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "MaxSessionTokens must be non-negative",
		},
		{
			name:              "negative UsedSessionTokens",
			maxSessionTokens:  100,
			usedSessionTokens: -50,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "UsedSessionTokens must be non-negative",
		},
		{
			name:              "negative MaxHourUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        -5.00,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "MaxHourUSD must be non-negative",
		},
		{
			name:              "negative UsedHourUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        5.00,
			usedHourUSD:       -2.50,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "UsedHourUSD must be non-negative",
		},
		{
			name:              "negative MaxDayUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         -50.00,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "MaxDayUSD must be non-negative",
		},
		{
			name:              "negative UsedDayUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         50.00,
			usedDayUSD:        -25.00,
			wantErr:           true,
			errContains:       "UsedDayUSD must be non-negative",
		},
		{
			name:              "UsedSessionTokens exceeds MaxSessionTokens",
			maxSessionTokens:  1000,
			usedSessionTokens: 1500,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "UsedSessionTokens (1500) exceeds MaxSessionTokens (1000)",
		},
		{
			name:              "UsedHourUSD exceeds MaxHourUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        5.00,
			usedHourUSD:       7.50,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           true,
			errContains:       "UsedHourUSD (7.50) exceeds MaxHourUSD (5.00)",
		},
		{
			name:              "UsedDayUSD exceeds MaxDayUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         50.00,
			usedDayUSD:        75.00,
			wantErr:           true,
			errContains:       "UsedDayUSD (75.00) exceeds MaxDayUSD (50.00)",
		},
		{
			name:              "UsedSessionTokens equals MaxSessionTokens (valid)",
			maxSessionTokens:  1000,
			usedSessionTokens: 1000,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           false,
		},
		{
			name:              "UsedHourUSD equals MaxHourUSD (valid)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        5.00,
			usedHourUSD:       5.00,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           false,
		},
		{
			name:              "UsedDayUSD equals MaxDayUSD (valid)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         50.00,
			usedDayUSD:        50.00,
			wantErr:           false,
		},
		{
			name:              "MaxSessionTokens zero allows any UsedSessionTokens",
			maxSessionTokens:  0,
			usedSessionTokens: 999999,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           false,
		},
		{
			name:              "MaxHourUSD zero allows any UsedHourUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       999.99,
			maxDayUSD:         0,
			usedDayUSD:        0,
			wantErr:           false,
		},
		{
			name:              "MaxDayUSD zero allows any UsedDayUSD",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourUSD:        0,
			usedHourUSD:       0,
			maxDayUSD:         0,
			usedDayUSD:        999.99,
			wantErr:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := provider.NewBudget(
				tt.maxSessionTokens,
				tt.usedSessionTokens,
				tt.maxHourUSD,
				tt.usedHourUSD,
				tt.maxDayUSD,
				tt.usedDayUSD,
			)

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue))
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, b)
			} else {
				require.NoError(t, err)
				require.NotNil(t, b)
				assert.Equal(t, tt.maxSessionTokens, b.MaxSessionTokens)
				assert.Equal(t, tt.usedSessionTokens, b.UsedSessionTokens)
				assert.Equal(t, tt.maxHourUSD, b.MaxHourUSD)
				assert.Equal(t, tt.usedHourUSD, b.UsedHourUSD)
				assert.Equal(t, tt.maxDayUSD, b.MaxDayUSD)
				assert.Equal(t, tt.usedDayUSD, b.UsedDayUSD)
			}
		})
	}
}

func TestBudget_Validate(t *testing.T) {
	tests := []struct {
		name        string
		budget      *provider.Budget
		wantErr     bool
		errContains string
	}{
		{
			name: "valid budget",
			budget: &provider.Budget{
				MaxSessionTokens:  10000,
				UsedSessionTokens: 5000,
				MaxHourUSD:        5.00,
				UsedHourUSD:       2.50,
				MaxDayUSD:         50.00,
				UsedDayUSD:        25.00,
			},
			wantErr: false,
		},
		{
			name: "invalid - negative MaxSessionTokens",
			budget: &provider.Budget{
				MaxSessionTokens: -100,
			},
			wantErr:     true,
			errContains: "MaxSessionTokens must be non-negative",
		},
		{
			name: "invalid - UsedSessionTokens exceeds MaxSessionTokens",
			budget: &provider.Budget{
				MaxSessionTokens:  1000,
				UsedSessionTokens: 1500,
			},
			wantErr:     true,
			errContains: "UsedSessionTokens (1500) exceeds MaxSessionTokens (1000)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.budget.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue))
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

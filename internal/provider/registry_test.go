// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// atomicInt64 wraps atomic.Int64 for concurrent counter tracking in tests.
type atomicInt64 = atomic.Int64

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
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

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

	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))
	require.NoError(t, reg.SetOverride("homelab", "openai/gpt-4.1"))

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

	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))
	require.NoError(t, reg.SetFailover([]string{"openai/gpt-4.1"}))

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

	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))
	require.NoError(t, reg.SetFailover([]string{"openai/gpt-4.1"}))

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
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

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

	// Register providers so SetFailover validation passes.
	reg.Register("a", &mockRegistryProvider{mockProviderBase: newMockProviderBase("a", true)})
	reg.Register("b", &mockRegistryProvider{mockProviderBase: newMockProviderBase("b", true)})
	reg.Register("c", &mockRegistryProvider{mockProviderBase: newMockProviderBase("c", true)})

	// Set failover chain with 3 entries → 4 attempts total.
	require.NoError(t, reg.SetFailover([]string{"a/model", "b/model", "c/model"}))
	assert.Equal(t, 4, reg.MaxAttempts())
}

func TestRegistry_BudgetEnforcement_HourlyCents(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

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
				b, _ := provider.NewBudget(0, 0, 500, 300, 0, 0)
				return b
			}(),
			wantErr: false,
		},
		{
			name: "hourly budget exactly met",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 500, 500, 0, 0)
				return b
			}(),
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "hourly budget slightly under limit",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 500, 499, 0, 0)
				return b
			}(),
			wantErr: false, // Under limit, should succeed
		},
		{
			name: "hourly budget zero means unlimited",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 99999, 0, 0)
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

func TestRegistry_BudgetEnforcement_DailyCents(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

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
				b, _ := provider.NewBudget(0, 0, 0, 0, 5000, 2500)
				return b
			}(),
			wantErr: false,
		},
		{
			name: "daily budget exactly met",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 5000, 5000)
				return b
			}(),
			wantErr: true,
			errCode: sigilerr.CodeProviderBudgetExceeded,
		},
		{
			name: "daily budget zero means unlimited",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 0, 99999)
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
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

	ctx := context.Background()

	tests := []struct {
		name    string
		budget  *provider.Budget
		wantErr bool
	}{
		{
			name: "all limits within bounds",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(100000, 5000, 500, 100, 5000, 1000)
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
				b, _ := provider.NewBudget(0, 0, 500, 500, 0, 0)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "daily at limit triggers routing rejection",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 5000, 5000)
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

func TestBudget_CentsFieldsExist(t *testing.T) {
	b, err := provider.NewBudget(100000, 0, 500, 0, 5000, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(500), b.MaxHourCents())
	assert.Equal(t, int64(5000), b.MaxDayCents())
}

func TestNewBudget_Validation(t *testing.T) {
	tests := []struct {
		name              string
		maxSessionTokens  int
		usedSessionTokens int
		maxHourCents      int64
		usedHourCents     int64
		maxDayCents       int64
		usedDayCents      int64
		wantErr           bool
		errContains       string
	}{
		{
			name:              "valid budget with all positive values",
			maxSessionTokens:  10000,
			usedSessionTokens: 5000,
			maxHourCents:      500,
			usedHourCents:     250,
			maxDayCents:       5000,
			usedDayCents:      2500,
			wantErr:           false,
		},
		{
			name:              "zero budget (all zeros - unlimited)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           false,
		},
		{
			name:              "negative MaxSessionTokens",
			maxSessionTokens:  -100,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "MaxSessionTokens must be non-negative",
		},
		{
			name:              "negative UsedSessionTokens",
			maxSessionTokens:  100,
			usedSessionTokens: -50,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "UsedSessionTokens must be non-negative",
		},
		{
			name:              "negative MaxHourCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      -500,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "MaxHourCents must be non-negative",
		},
		{
			name:              "negative UsedHourCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      500,
			usedHourCents:     -250,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "UsedHourCents must be non-negative",
		},
		{
			name:              "negative MaxDayCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       -5000,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "MaxDayCents must be non-negative",
		},
		{
			name:              "negative UsedDayCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       5000,
			usedDayCents:      -2500,
			wantErr:           true,
			errContains:       "UsedDayCents must be non-negative",
		},
		{
			name:              "UsedSessionTokens exceeds MaxSessionTokens",
			maxSessionTokens:  1000,
			usedSessionTokens: 1500,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "UsedSessionTokens (1500) exceeds MaxSessionTokens (1000)",
		},
		{
			name:              "UsedHourCents exceeds MaxHourCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      500,
			usedHourCents:     750,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           true,
			errContains:       "UsedHourCents (750) exceeds MaxHourCents (500)",
		},
		{
			name:              "UsedDayCents exceeds MaxDayCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       5000,
			usedDayCents:      7500,
			wantErr:           true,
			errContains:       "UsedDayCents (7500) exceeds MaxDayCents (5000)",
		},
		{
			name:              "UsedSessionTokens equals MaxSessionTokens (valid)",
			maxSessionTokens:  1000,
			usedSessionTokens: 1000,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           false,
		},
		{
			name:              "UsedHourCents equals MaxHourCents (valid)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      500,
			usedHourCents:     500,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           false,
		},
		{
			name:              "UsedDayCents equals MaxDayCents (valid)",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       5000,
			usedDayCents:      5000,
			wantErr:           false,
		},
		{
			name:              "MaxSessionTokens zero allows any UsedSessionTokens",
			maxSessionTokens:  0,
			usedSessionTokens: 999999,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           false,
		},
		{
			name:              "MaxHourCents zero allows any UsedHourCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     99999,
			maxDayCents:       0,
			usedDayCents:      0,
			wantErr:           false,
		},
		{
			name:              "MaxDayCents zero allows any UsedDayCents",
			maxSessionTokens:  0,
			usedSessionTokens: 0,
			maxHourCents:      0,
			usedHourCents:     0,
			maxDayCents:       0,
			usedDayCents:      99999,
			wantErr:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := provider.NewBudget(
				tt.maxSessionTokens,
				tt.usedSessionTokens,
				tt.maxHourCents,
				tt.usedHourCents,
				tt.maxDayCents,
				tt.usedDayCents,
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
				assert.Equal(t, tt.maxSessionTokens, b.MaxSessionTokens())
				assert.Equal(t, tt.usedSessionTokens, b.UsedSessionTokens())
				assert.Equal(t, tt.maxHourCents, b.MaxHourCents())
				assert.Equal(t, tt.usedHourCents, b.UsedHourCents())
				assert.Equal(t, tt.maxDayCents, b.MaxDayCents())
				assert.Equal(t, tt.usedDayCents, b.UsedDayCents())
			}
		})
	}
}

// TestRegistry_BudgetMidSessionExhaustion tests budget mid-session exhaustion.
// When a session at 900/1000 tokens consumes 200 more tokens mid-turn,
// the budget check at callLLM entry only checks 900 < 1000 (passes),
// but final count can exceed limit (1100 > 1000). This test documents
// the current behavior: routing allows the call but final usage can overrun.
func TestRegistry_BudgetMidSessionExhaustion(t *testing.T) {
	reg := provider.NewRegistry()
	anthropic := &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)}
	reg.Register("anthropic", anthropic)
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

	ctx := context.Background()

	// Session already at 900/1000 tokens.
	budget, err := provider.NewBudget(1000, 900, 0, 0, 0, 0)
	require.NoError(t, err)

	// Routing should succeed since 900 < 1000 at entry.
	p, model, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
	assert.Equal(t, "claude-sonnet-4-5", model)

	// Document behavior: the LLM call happens and can return 200 tokens,
	// pushing total to 1100 > 1000. Budget overrun is detected by caller
	// after the fact, not prevented at routing time.
	// This test documents the current design: routing checks budget at entry,
	// caller tracks actual usage and may exceed budget mid-turn.
}

func TestRegistry_SetDefault_UnregisteredProvider(t *testing.T) {
	reg := provider.NewRegistry()

	err := reg.SetDefault("nonexistent/model")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderNotFound))
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestRegistry_SetOverride_UnregisteredProvider(t *testing.T) {
	reg := provider.NewRegistry()

	err := reg.SetOverride("ws-1", "nonexistent/model")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderNotFound))
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestRegistry_SetFailover_UnregisteredProvider(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("openai", &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", true)})

	// First ref is valid, second is not.
	err := reg.SetFailover([]string{"openai/gpt-4.1", "nonexistent/model"})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderNotFound))
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestRegistry_SetFailover_AllRegistered(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("openai", &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", true)})
	reg.Register("google", &mockRegistryProvider{mockProviderBase: newMockProviderBase("google", true)})

	err := reg.SetFailover([]string{"openai/gpt-4.1", "google/gemini-2.5-pro"})
	require.NoError(t, err)
}

// --- Concurrent access tests ---

func TestRegistry_ConcurrentRouteWithBudgetChecks(t *testing.T) {
	// Concurrent RouteWithBudget calls with different budget states should not
	// race on registry internal state. Each call creates its own Budget so the
	// contention is on the registry's RWMutex-protected provider map.
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)})
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	// Barrier: all goroutines start simultaneously.
	start := make(chan struct{})
	ctx := context.Background()

	// Half the goroutines route with budget under limit (should succeed).
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, err := provider.NewBudget(1000, 500, 500, 200, 5000, 1000)
				require.NoError(t, err)
				p, model, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				require.NoError(t, err)
				assert.Equal(t, "anthropic", p.Name())
				assert.Equal(t, "claude-sonnet-4-5", model)
			}
		}()
	}

	// Other half route with exhausted budget (should fail).
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, err := provider.NewBudget(1000, 1000, 0, 0, 0, 0)
				require.NoError(t, err)
				_, _, err = reg.RouteWithBudget(ctx, "", "", budget, nil)
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded))
			}
		}()
	}

	close(start)
	wg.Wait()
}

func TestRegistry_ConcurrentRouteWithDifferentBudgetTypes(t *testing.T) {
	// Concurrent RouteWithBudget calls exercising token, hourly, and daily
	// budget paths simultaneously to verify no races on shared registry state.
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)})
	reg.Register("openai", &mockRegistryProvider{mockProviderBase: newMockProviderBase("openai", true)})
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))
	require.NoError(t, reg.SetFailover([]string{"openai/gpt-4.1"}))

	const goroutines = 10
	const iterations = 50

	var wg sync.WaitGroup
	start := make(chan struct{})
	ctx := context.Background()

	tests := []struct {
		name    string
		budget  func() *provider.Budget
		wantErr bool
	}{
		{
			name: "token budget under limit",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(1000, 500, 0, 0, 0, 0)
				return b
			},
			wantErr: false,
		},
		{
			name: "token budget exhausted",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(1000, 1000, 0, 0, 0, 0)
				return b
			},
			wantErr: true,
		},
		{
			name: "hourly budget exhausted",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 500, 500, 0, 0)
				return b
			},
			wantErr: true,
		},
		{
			name: "daily budget exhausted",
			budget: func() *provider.Budget {
				b, _ := provider.NewBudget(0, 0, 0, 0, 5000, 5000)
				return b
			},
			wantErr: true,
		},
		{
			name: "nil budget passes",
			budget: func() *provider.Budget {
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(wantErr bool, budgetFn func() *provider.Budget) {
				defer wg.Done()
				<-start
				for j := 0; j < iterations; j++ {
					_, _, err := reg.RouteWithBudget(ctx, "", "", budgetFn(), nil)
					if wantErr {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
					}
				}
			}(tt.wantErr, tt.budget)
		}
	}

	close(start)
	wg.Wait()
}

func TestRegistry_ConcurrentRegisterAndRoute(t *testing.T) {
	// Concurrent Register calls interleaved with Route calls exercise the
	// write-lock (Register) vs read-lock (Route) contention on the registry.
	reg := provider.NewRegistry()

	// Pre-register a default so Route has a valid target.
	reg.Register("base", &mockRegistryProvider{mockProviderBase: newMockProviderBase("base", true)})
	require.NoError(t, reg.SetDefault("base/model"))

	const goroutines = 10
	const iterations = 50

	var wg sync.WaitGroup
	start := make(chan struct{})
	ctx := context.Background()

	// Writers: register new providers concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				name := "provider-" + strconv.Itoa(id) + "-" + strconv.Itoa(j)
				reg.Register(name, &mockRegistryProvider{
					mockProviderBase: newMockProviderBase(name, true),
				})
			}
		}(i)
	}

	// Readers: route concurrently with budget checks.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, _ := provider.NewBudget(10000, j, 0, 0, 0, 0)
				p, _, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				require.NoError(t, err)
				assert.Equal(t, "base", p.Name())
			}
		}()
	}

	// Readers: Get concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				p, err := reg.Get("base")
				require.NoError(t, err)
				assert.Equal(t, "base", p.Name())
			}
		}()
	}

	close(start)
	wg.Wait()
}

func TestRegistry_ConcurrentBudgetExhaustionRace(t *testing.T) {
	// Simulates the scenario where multiple goroutines race to route with
	// budgets near the exhaustion boundary. Each goroutine creates a budget
	// at exactly limit-1 (passes) or exactly limit (fails). We verify that
	// the budget check correctly returns the expected result for each case
	// even under heavy contention on the registry's read lock.
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockRegistryProvider{mockProviderBase: newMockProviderBase("anthropic", true)})
	require.NoError(t, reg.SetDefault("anthropic/claude-sonnet-4-5"))

	const goroutines = 20
	const iterations = 100

	var wg sync.WaitGroup
	start := make(chan struct{})
	ctx := context.Background()

	var (
		passCount atomicInt64
		failCount atomicInt64
	)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				// Alternate between just-under and at-limit budgets.
				var budget *provider.Budget
				if (id+j)%2 == 0 {
					budget, _ = provider.NewBudget(1000, 999, 0, 0, 0, 0) // under limit
				} else {
					budget, _ = provider.NewBudget(1000, 1000, 0, 0, 0, 0) // at limit
				}
				_, _, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				if err == nil {
					passCount.Add(1)
				} else {
					assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded))
					failCount.Add(1)
				}
			}
		}(i)
	}

	close(start)
	wg.Wait()

	// Every goroutine did iterations calls. Verify totals are consistent.
	total := passCount.Load() + failCount.Load()
	assert.Equal(t, int64(goroutines*iterations), total)
	// Both pass and fail paths must have been exercised.
	assert.Greater(t, passCount.Load(), int64(0), "expected some routes to pass budget check")
	assert.Greater(t, failCount.Load(), int64(0), "expected some routes to fail budget check")
}

func TestRegistry_ConcurrentFailoverWithBudget(t *testing.T) {
	// Concurrent RouteWithBudget with failover exercised: primary is down,
	// fallback is up. Multiple goroutines route simultaneously, some with
	// valid budgets and some with exhausted budgets.
	reg := provider.NewRegistry()
	reg.Register("primary", &mockRegistryProvider{mockProviderBase: newMockProviderBase("primary", false)})
	reg.Register("fallback", &mockRegistryProvider{mockProviderBase: newMockProviderBase("fallback", true)})
	require.NoError(t, reg.SetDefault("primary/model-a"))
	require.NoError(t, reg.SetFailover([]string{"fallback/model-b"}))

	const goroutines = 10
	const iterations = 50

	var wg sync.WaitGroup
	start := make(chan struct{})
	ctx := context.Background()

	// Goroutines with valid budget: should failover to fallback.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, _ := provider.NewBudget(10000, 100, 0, 0, 0, 0)
				p, model, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				require.NoError(t, err)
				assert.Equal(t, "fallback", p.Name())
				assert.Equal(t, "model-b", model)
			}
		}()
	}

	// Goroutines with exhausted budget: should fail before trying any provider.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, _ := provider.NewBudget(100, 100, 0, 0, 0, 0)
				_, _, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderBudgetExceeded))
			}
		}()
	}

	close(start)
	wg.Wait()
}

func TestRegistry_ConcurrentConfigMutationWithBudgetRouting(t *testing.T) {
	// Exercises concurrent writes (SetDefault, SetOverride, SetFailover) against
	// concurrent reads (RouteWithBudget) to stress the RWMutex boundaries.
	reg := provider.NewRegistry()
	reg.Register("a", &mockRegistryProvider{mockProviderBase: newMockProviderBase("a", true)})
	reg.Register("b", &mockRegistryProvider{mockProviderBase: newMockProviderBase("b", true)})
	reg.Register("c", &mockRegistryProvider{mockProviderBase: newMockProviderBase("c", true)})
	require.NoError(t, reg.SetDefault("a/model"))

	const goroutines = 10
	const iterations = 50

	var wg sync.WaitGroup
	start := make(chan struct{})
	ctx := context.Background()

	// Config writers: cycle the default provider.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		refs := []string{"a/model", "b/model", "c/model"}
		for j := 0; j < goroutines*iterations; j++ {
			_ = reg.SetDefault(refs[j%len(refs)])
		}
	}()

	// Config writers: cycle workspace overrides.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		refs := []string{"a/model", "b/model", "c/model"}
		for j := 0; j < goroutines*iterations; j++ {
			_ = reg.SetOverride("ws-1", refs[j%len(refs)])
		}
	}()

	// Config writers: cycle failover chain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		chains := [][]string{
			{"b/model"},
			{"c/model"},
			{"b/model", "c/model"},
		}
		for j := 0; j < goroutines*iterations; j++ {
			_ = reg.SetFailover(chains[j%len(chains)])
		}
	}()

	// Readers: route with budget, accepting any valid provider.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				budget, _ := provider.NewBudget(10000, 100, 500, 50, 5000, 500)
				p, _, err := reg.RouteWithBudget(ctx, "", "", budget, nil)
				// Should always succeed: all providers are available and budget is under limit.
				require.NoError(t, err)
				// Provider name must be one of the registered ones.
				assert.Contains(t, []string{"a", "b", "c"}, p.Name())
			}
		}()
	}

	close(start)
	wg.Wait()
}

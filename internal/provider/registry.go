// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Budget defines token and USD budget constraints for a routing request.
// The caller (agent loop) is responsible for tracking cumulative spend
// and populating these fields; routing only enforces the limits.
type Budget struct {
	MaxSessionTokens  int
	UsedSessionTokens int

	// USD budget constraints (0 = unlimited).
	MaxHourUSD  float64
	UsedHourUSD float64
	MaxDayUSD   float64
	UsedDayUSD  float64
}

// Registry manages provider registration, lookup, and routing with
// failover and budget enforcement. It implements the Router interface.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider

	defaultRef string            // "provider/model" format
	overrides  map[string]string // workspaceID → "provider/model"
	failover   []string          // ordered list of "provider/model" refs
}

// Compile-time check that Registry implements Router.
var _ Router = (*Registry)(nil)

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		overrides: make(map[string]string),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(name string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = p
}

// RegisterProvider adds a provider to the registry (Router interface).
func (r *Registry) RegisterProvider(name string, p Provider) error {
	r.Register(name, p)
	return nil
}

// Get retrieves a provider by name.
func (r *Registry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	if !ok {
		return nil, sigilerr.New(
			sigilerr.CodeProviderNotFound,
			"provider not found: "+name,
			sigilerr.FieldProvider(name),
		)
	}
	return p, nil
}

// SetDefault sets the default "provider/model" reference used when no
// workspace override matches.
func (r *Registry) SetDefault(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultRef = ref
}

// SetOverride sets a workspace-specific "provider/model" override.
func (r *Registry) SetOverride(workspaceID, ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.overrides[workspaceID] = ref
}

// SetFailover sets the ordered failover chain of "provider/model" refs.
func (r *Registry) SetFailover(chain []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failover = chain
}

// MaxAttempts returns 1 (primary) + len(failover chain) so the agent loop
// caps its retry count to exactly the number of configured provider candidates.
func (r *Registry) MaxAttempts() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return 1 + len(r.failover)
}

// Route selects a provider for the given workspace and model name.
// It implements the Router interface. When modelName is empty the
// default (or workspace override) is used.
func (r *Registry) Route(ctx context.Context, workspaceID, modelName string) (Provider, string, error) {
	return r.RouteWithBudget(ctx, workspaceID, modelName, nil, nil)
}

// RouteWithBudget is like Route but also enforces token budget constraints.
// The exclude list contains provider names to skip (already-tried providers
// in the current failover sequence), ensuring failover progresses even for
// providers that don't implement HealthReporter.
func (r *Registry) RouteWithBudget(ctx context.Context, workspaceID, modelName string, budget *Budget, exclude []string) (Provider, string, error) {
	// 1. Check budget.
	if budget != nil && budget.MaxSessionTokens > 0 && budget.UsedSessionTokens >= budget.MaxSessionTokens {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderBudgetExceeded,
			"budget exceeded: used "+itoa(budget.UsedSessionTokens)+" of "+itoa(budget.MaxSessionTokens)+" tokens",
		)
	}

	// 1b. Check hourly USD budget.
	if budget != nil && budget.MaxHourUSD > 0 && budget.UsedHourUSD >= budget.MaxHourUSD {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderBudgetExceeded,
			"budget exceeded: hourly USD spend $"+formatUSD(budget.UsedHourUSD)+" of $"+formatUSD(budget.MaxHourUSD)+" limit",
		)
	}

	// 1c. Check daily USD budget.
	if budget != nil && budget.MaxDayUSD > 0 && budget.UsedDayUSD >= budget.MaxDayUSD {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderBudgetExceeded,
			"budget exceeded: daily USD spend $"+formatUSD(budget.UsedDayUSD)+" of $"+formatUSD(budget.MaxDayUSD)+" limit",
		)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// 2. Determine the ref to use.
	ref, err := r.resolveRef(workspaceID, modelName)
	if err != nil {
		return nil, "", err
	}
	if ref == "" {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderNoDefault,
			"no default provider configured",
		)
	}

	// 3. Try the primary ref (skip if provider is in exclude list).
	provName, _ := parseRef(ref)
	if !slices.Contains(exclude, provName) {
		p, model, err := r.tryRef(ctx, ref)
		if err == nil {
			return p, model, nil
		}
	}

	// 4. Walk failover chain (skip excluded providers).
	for _, fallback := range r.failover {
		fbProv, _ := parseRef(fallback)
		if slices.Contains(exclude, fbProv) {
			continue
		}
		p, model, err := r.tryRef(ctx, fallback)
		if err == nil {
			return p, model, nil
		}
	}

	// 5. All exhausted.
	return nil, "", sigilerr.New(
		sigilerr.CodeProviderAllUnavailable,
		"all providers unavailable: no healthy provider found",
	)
}

// Close shuts down all registered providers.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for _, p := range r.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return sigilerr.Join(errs...)
	}
	return nil
}

// resolveRef determines which "provider/model" ref to use.
// Caller must hold r.mu (at least RLock).
// Returns an error for non-qualified model names (missing "provider/" prefix).
func (r *Registry) resolveRef(workspaceID, modelName string) (string, error) {
	// Explicit model name must use "provider/model" format.
	if modelName != "" && modelName != "default" {
		if !strings.Contains(modelName, "/") {
			return "", sigilerr.Errorf(
				sigilerr.CodeProviderInvalidModelRef,
				"model name %q must use provider/model format", modelName,
			)
		}
		return modelName, nil
	}

	// Workspace override.
	if workspaceID != "" {
		if override, ok := r.overrides[workspaceID]; ok {
			return override, nil
		}
	}

	return r.defaultRef, nil
}

// tryRef parses a "provider/model" ref, looks up the provider, and checks
// availability. Caller must hold r.mu (at least RLock).
func (r *Registry) tryRef(ctx context.Context, ref string) (Provider, string, error) {
	providerName, model := parseRef(ref)

	p, ok := r.providers[providerName]
	if !ok {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderNotFound,
			"provider not found: "+providerName,
			sigilerr.FieldProvider(providerName),
		)
	}

	if !p.Available(ctx) {
		return nil, "", sigilerr.New(
			sigilerr.CodeProviderUpstreamFailure,
			"provider unavailable: "+providerName,
			sigilerr.FieldProvider(providerName),
		)
	}

	return p, model, nil
}

// parseRef splits a "provider/model" reference on the first "/".
func parseRef(ref string) (providerName, model string) {
	idx := strings.Index(ref, "/")
	if idx < 0 {
		return ref, ""
	}
	return ref[:idx], ref[idx+1:]
}

// formatUSD formats a float64 as a two-decimal USD string (e.g. "5.00").
func formatUSD(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// Reverse.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Budget defines token and monetary budget constraints for a routing request.
// The caller (agent loop) is responsible for tracking cumulative spend
// and populating these fields; routing only enforces the limits.
// Monetary values are stored as int64 cents to avoid floating-point rounding.
type Budget struct {
	maxSessionTokens  int
	usedSessionTokens int

	// Monetary budget constraints in cents (0 = unlimited).
	maxHourCents  int64
	usedHourCents int64
	maxDayCents   int64
	usedDayCents  int64
}

// NewBudget creates a validated Budget. Monetary fields are in cents. It returns an error if:
// - Any field is negative
// - UsedSessionTokens > MaxSessionTokens (when MaxSessionTokens > 0)
// - UsedHourCents > MaxHourCents (when MaxHourCents > 0)
// - UsedDayCents > MaxDayCents (when MaxDayCents > 0)
func NewBudget(maxSessionTokens, usedSessionTokens int, maxHourCents, usedHourCents, maxDayCents, usedDayCents int64) (*Budget, error) {
	b := &Budget{
		maxSessionTokens:  maxSessionTokens,
		usedSessionTokens: usedSessionTokens,
		maxHourCents:      maxHourCents,
		usedHourCents:     usedHourCents,
		maxDayCents:       maxDayCents,
		usedDayCents:      usedDayCents,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate checks that all budget fields are valid.
func (b *Budget) Validate() error {
	if b.maxSessionTokens < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "MaxSessionTokens must be non-negative, got %d", b.maxSessionTokens)
	}
	if b.usedSessionTokens < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedSessionTokens must be non-negative, got %d", b.usedSessionTokens)
	}
	if b.maxHourCents < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "MaxHourCents must be non-negative, got %d", b.maxHourCents)
	}
	if b.usedHourCents < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedHourCents must be non-negative, got %d", b.usedHourCents)
	}
	if b.maxDayCents < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "MaxDayCents must be non-negative, got %d", b.maxDayCents)
	}
	if b.usedDayCents < 0 {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedDayCents must be non-negative, got %d", b.usedDayCents)
	}

	// Check that usage doesn't exceed limits (when limits are set).
	if b.maxSessionTokens > 0 && b.usedSessionTokens > b.maxSessionTokens {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedSessionTokens (%d) exceeds MaxSessionTokens (%d)", b.usedSessionTokens, b.maxSessionTokens)
	}
	if b.maxHourCents > 0 && b.usedHourCents > b.maxHourCents {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedHourCents (%d) exceeds MaxHourCents (%d)", b.usedHourCents, b.maxHourCents)
	}
	if b.maxDayCents > 0 && b.usedDayCents > b.maxDayCents {
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "UsedDayCents (%d) exceeds MaxDayCents (%d)", b.usedDayCents, b.maxDayCents)
	}

	return nil
}

// MaxSessionTokens returns the maximum tokens allowed per session.
func (b *Budget) MaxSessionTokens() int {
	return b.maxSessionTokens
}

// UsedSessionTokens returns the tokens already used in the session.
func (b *Budget) UsedSessionTokens() int {
	return b.usedSessionTokens
}

// MaxHourCents returns the maximum hourly spend limit in cents.
func (b *Budget) MaxHourCents() int64 {
	return b.maxHourCents
}

// UsedHourCents returns the amount spent in the current hour in cents.
func (b *Budget) UsedHourCents() int64 {
	return b.usedHourCents
}

// MaxDayCents returns the maximum daily spend limit in cents.
func (b *Budget) MaxDayCents() int64 {
	return b.maxDayCents
}

// UsedDayCents returns the amount spent in the current day in cents.
func (b *Budget) UsedDayCents() int64 {
	return b.usedDayCents
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
// workspace override matches. Returns an error if the provider portion
// of the ref is not registered.
func (r *Registry) SetDefault(ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	provName, _ := parseRef(ref)
	if _, ok := r.providers[provName]; !ok {
		return sigilerr.New(
			sigilerr.CodeProviderNotFound,
			"SetDefault: provider not registered: "+provName,
			sigilerr.FieldProvider(provName),
		)
	}
	r.defaultRef = ref
	return nil
}

// SetOverride sets a workspace-specific "provider/model" override.
// Returns an error if the provider portion of the ref is not registered.
func (r *Registry) SetOverride(workspaceID, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	provName, _ := parseRef(ref)
	if _, ok := r.providers[provName]; !ok {
		return sigilerr.New(
			sigilerr.CodeProviderNotFound,
			"SetOverride: provider not registered: "+provName,
			sigilerr.FieldProvider(provName),
		)
	}
	r.overrides[workspaceID] = ref
	return nil
}

// SetFailover sets the ordered failover chain of "provider/model" refs.
// Returns an error if any provider portion of the refs is not registered.
func (r *Registry) SetFailover(chain []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, ref := range chain {
		provName, _ := parseRef(ref)
		if _, ok := r.providers[provName]; !ok {
			return sigilerr.New(
				sigilerr.CodeProviderNotFound,
				"SetFailover: provider not registered: "+provName,
				sigilerr.FieldProvider(provName),
			)
		}
	}
	r.failover = append([]string(nil), chain...)
	return nil
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
	if budget != nil {
		if err := checkBudgetLimit(budget.MaxSessionTokens(), budget.UsedSessionTokens(),
			func(used, max int) string {
				return "budget exceeded: used " + strconv.Itoa(used) + " of " + strconv.Itoa(max) + " tokens"
			}); err != nil {
			return nil, "", err
		}

		// 1b. Check hourly budget (cents).
		if err := checkBudgetLimit(budget.MaxHourCents(), budget.UsedHourCents(),
			func(used, max int64) string {
				return "budget exceeded: hourly spend " + formatCents(used) + " of " + formatCents(max) + " limit"
			}); err != nil {
			return nil, "", err
		}

		// 1c. Check daily budget (cents).
		if err := checkBudgetLimit(budget.MaxDayCents(), budget.UsedDayCents(),
			func(used, max int64) string {
				return "budget exceeded: daily spend " + formatCents(used) + " of " + formatCents(max) + " limit"
			}); err != nil {
			return nil, "", err
		}
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

// formatCents formats an int64 cents value as a USD string (e.g. 500 → "$5.00").
func formatCents(cents int64) string {
	return fmt.Sprintf("$%d.%02d", cents/100, cents%100)
}

// checkBudgetLimit returns nil if max is 0 (unlimited) or used < max.
func checkBudgetLimit[T int | int64](max, used T, formatMsg func(used, max T) string) error {
	if max > 0 && used >= max {
		return sigilerr.New(sigilerr.CodeProviderBudgetExceeded, formatMsg(used, max))
	}
	return nil
}

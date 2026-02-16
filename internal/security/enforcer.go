// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

type pluginCapabilities struct {
	allow CapabilitySet
	deny  CapabilitySet
}

// CheckRequest describes a capability check for a plugin invocation.
type CheckRequest struct {
	Plugin          string
	Capability      string
	WorkspaceID     string
	WorkspaceAllow  CapabilitySet
	UserPermissions CapabilitySet
}

// Validate checks that required fields are non-empty and that Capability is a valid glob pattern.
func (r CheckRequest) Validate() error {
	if r.Plugin == "" {
		return sigilerr.New(sigilerr.CodeSecurityInvalidInput, "CheckRequest: Plugin must not be empty")
	}
	if r.Capability == "" {
		return sigilerr.New(sigilerr.CodeSecurityInvalidInput, "CheckRequest: Capability must not be empty")
	}
	if _, err := filepath.Match(r.Capability, ""); err != nil {
		return sigilerr.Errorf(sigilerr.CodeSecurityInvalidInput, "CheckRequest: Capability contains invalid glob pattern: %w", err)
	}
	return nil
}

// Enforcer applies plugin, workspace, and user capability policy checks.
type Enforcer struct {
	mu             sync.RWMutex
	audit          store.AuditStore
	plugins        map[string]pluginCapabilities
	auditIDCounter uint64 // Per-enforcer audit ID sequence (not shared globally)
}

// NewEnforcer creates an Enforcer that writes decision audits to audit.
// If audit is nil, audit logging is silently disabled (all checks still enforced).
func NewEnforcer(audit store.AuditStore) *Enforcer {
	if audit == nil {
		slog.Warn("enforcer created with nil audit store; audit logging disabled")
	}

	return &Enforcer{
		audit:   audit,
		plugins: make(map[string]pluginCapabilities),
	}
}

// RegisterPlugin registers a plugin with allow and deny capability sets.
func (e *Enforcer) RegisterPlugin(name string, allow, deny CapabilitySet) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.plugins[name] = pluginCapabilities{allow: allow, deny: deny}
}

// UnregisterPlugin unregisters a plugin's capability policy.
func (e *Enforcer) UnregisterPlugin(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.plugins, name)
}

// Check enforces plugin, workspace, and user capability policy constraints.
func (e *Enforcer) Check(ctx context.Context, req CheckRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	e.mu.RLock()
	pluginCaps, ok := e.plugins[req.Plugin]
	e.mu.RUnlock()

	if !ok {
		return e.deny(ctx, req, "plugin_not_registered", false, false, false, false)
	}

	pluginAllow, err := pluginCaps.allow.Contains(req.Capability)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecurityCapabilityInvalid, "checking plugin allow capabilities for %q", req.Plugin)
	}
	if !pluginAllow {
		return e.deny(ctx, req, "plugin_allow_missing", pluginAllow, false, false, false)
	}

	pluginDeny, err := pluginCaps.deny.Contains(req.Capability)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecurityCapabilityInvalid, "checking plugin deny capabilities for %q", req.Plugin)
	}
	if pluginDeny {
		return e.deny(ctx, req, "plugin_deny_match", pluginAllow, pluginDeny, false, false)
	}

	workspaceAllow, err := req.WorkspaceAllow.Contains(req.Capability)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecurityCapabilityInvalid, "checking workspace capabilities")
	}
	if !workspaceAllow {
		return e.deny(ctx, req, "workspace_allow_missing", pluginAllow, pluginDeny, workspaceAllow, false)
	}

	userAllow, err := req.UserPermissions.Contains(req.Capability)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecurityCapabilityInvalid, "checking user permissions")
	}
	if !userAllow {
		return e.deny(ctx, req, "user_permission_missing", pluginAllow, pluginDeny, workspaceAllow, userAllow)
	}

	// Audit logging is best-effort to prevent cascading failures from a flaky audit backend.
	// In compliance-critical environments, consider making this configurable (fail-closed).
	if err := e.auditDecision(ctx, req, "allowed", "ok", pluginAllow, pluginDeny, workspaceAllow, userAllow); err != nil {
		slog.Warn("audit log failure on allowed decision (best-effort, not blocking)",
			"plugin", req.Plugin,
			"capability", req.Capability,
			"error", err,
		)
	}

	return nil
}

func (e *Enforcer) deny(
	ctx context.Context,
	req CheckRequest,
	reason string,
	pluginAllow bool,
	pluginDeny bool,
	workspaceAllow bool,
	userAllow bool,
) error {
	deniedErr := sigilerr.Errorf(
		sigilerr.CodePluginCapabilityDenied,
		"capability %q denied for plugin %q: %s",
		req.Capability,
		req.Plugin,
		reason,
	)

	// Audit logging is best-effort to prevent cascading failures from a flaky audit backend.
	// In compliance-critical environments, consider making this configurable (fail-closed).
	if err := e.auditDecision(ctx, req, "denied", reason, pluginAllow, pluginDeny, workspaceAllow, userAllow); err != nil {
		slog.Warn("audit log failure on denied decision (best-effort, not blocking)",
			"plugin", req.Plugin,
			"capability", req.Capability,
			"error", err,
		)
	}

	return deniedErr
}

func (e *Enforcer) auditDecision(
	ctx context.Context,
	req CheckRequest,
	result string,
	reason string,
	pluginAllow bool,
	pluginDeny bool,
	workspaceAllow bool,
	userAllow bool,
) error {
	if e.audit == nil {
		return nil
	}

	entry := &store.AuditEntry{
		ID:        e.nextAuditID(),
		Timestamp: time.Now().UTC(),
		Action:    "capability_check",
		// Actor represents the entity performing the action.
		// Currently set to plugin name for capability checks.
		// TODO(Phase 4): Integrate with user identity system to track actual user performing the action.
		Actor:       req.Plugin,
		Plugin:      req.Plugin,
		WorkspaceID: req.WorkspaceID,
		Details: map[string]any{
			"capability":      req.Capability,
			"reason":          reason,
			"plugin_allow":    pluginAllow,
			"plugin_deny":     pluginDeny,
			"workspace_allow": workspaceAllow,
			"user_allow":      userAllow,
		},
		Result: result,
	}

	if err := e.audit.Append(ctx, entry); err != nil {
		return sigilerr.Wrap(err, sigilerr.CodeStoreDatabaseFailure, "append audit entry")
	}

	return nil
}

func (e *Enforcer) nextAuditID() string {
	seq := atomic.AddUint64(&e.auditIDCounter, 1)
	return fmt.Sprintf("aud-%d-%d", time.Now().UTC().UnixNano(), seq)
}

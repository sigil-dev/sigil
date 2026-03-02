// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"log/slog"
	"path"
	"sort"
	"strings"
	"sync"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Compile-time interface satisfaction check.
var _ WorkspaceValidator = (*WorkspaceBinder)(nil)

const (
	maxWorkspaces        = 1000
	maxRulesPerWorkspace = 500
)

type workspaceRule struct {
	pattern string
	tools   []string
}

// WorkspaceBinder binds node ID patterns and tool allowlists to workspaces.
// Rules are additive: calling Bind or BindWithTools multiple times for the same
// workspace accumulates rules. AllowedTools merges tool sets across all matching
// rules at read time.
//
// All exported methods are safe for concurrent use.
type WorkspaceBinder struct {
	mu    sync.RWMutex
	rules map[string][]workspaceRule
}

func NewWorkspaceBinder() *WorkspaceBinder {
	return &WorkspaceBinder{
		rules: make(map[string][]workspaceRule),
	}
}

// Bind associates node ID patterns with a workspace. All nodes matching any
// pattern are allowed to access the workspace with unrestricted tool access.
func (b *WorkspaceBinder) Bind(workspaceID string, nodePatterns []string) error {
	ws := strings.TrimSpace(workspaceID)
	if ws == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "workspaceID must not be empty")
	}

	normalized := normalizeStrings(nodePatterns)
	if len(normalized) == 0 {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "nodePatterns must contain at least one non-empty value")
	}

	if err := validatePatterns(normalized); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Deduplicate against already-stored Bind rules (nil tools) for this workspace.
	newPatterns := b.deduplicatePatterns(ws, normalized)
	if len(newPatterns) == 0 {
		return nil // all patterns already bound
	}

	if err := b.checkLimits(ws, len(newPatterns)); err != nil {
		return err
	}

	for _, pattern := range newPatterns {
		b.rules[ws] = append(b.rules[ws], workspaceRule{pattern: pattern})
	}
	return nil
}

// BindWithTools associates a single node ID pattern with a workspace and
// restricts the node's tools to the given allowlist.
func (b *WorkspaceBinder) BindWithTools(workspaceID, nodePattern string, tools []string) error {
	ws := strings.TrimSpace(workspaceID)
	pattern := strings.TrimSpace(nodePattern)
	if ws == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "workspaceID must not be empty")
	}
	if pattern == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "nodePattern must not be empty")
	}

	if err := validatePatterns([]string{pattern}); err != nil {
		return err
	}

	normalizedTools := normalizeStrings(tools)
	for _, t := range normalizedTools {
		if strings.ContainsRune(t, ':') {
			return sigilerr.Errorf(sigilerr.CodeNodeBindInvalidInput, "tool name %q must not contain ':'", t)
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkLimits(ws, 1); err != nil {
		return err
	}

	b.rules[ws] = append(b.rules[ws], workspaceRule{
		pattern: pattern,
		tools:   normalizedTools,
	})
	return nil
}

// Unbind removes all rules for a workspace.
func (b *WorkspaceBinder) Unbind(workspaceID string) error {
	ws := strings.TrimSpace(workspaceID)
	if ws == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "workspaceID must not be empty")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.rules, ws)
	return nil
}

// UnbindPattern removes all rules matching a specific node pattern from a workspace.
func (b *WorkspaceBinder) UnbindPattern(workspaceID, nodePattern string) error {
	ws := strings.TrimSpace(workspaceID)
	pattern := strings.TrimSpace(nodePattern)
	if ws == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "workspaceID must not be empty")
	}
	if pattern == "" {
		return sigilerr.New(sigilerr.CodeNodeBindInvalidInput, "nodePattern must not be empty")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	rules := b.rules[ws]
	filtered := rules[:0]
	for _, r := range rules {
		if r.pattern != pattern {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		delete(b.rules, ws)
	} else {
		b.rules[ws] = filtered
	}
	return nil
}

// IsAllowed reports whether a node is permitted to access a workspace.
func (b *WorkspaceBinder) IsAllowed(workspaceID, nodeID string) bool {
	ws := strings.TrimSpace(workspaceID)
	node := strings.TrimSpace(nodeID)
	if ws == "" || node == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, rule := range b.rules[ws] {
		if ruleMatches(rule.pattern, node) {
			return true
		}
	}

	return false
}

// ValidateWorkspace checks whether a node is permitted in a workspace,
// satisfying the WorkspaceValidator interface.
func (b *WorkspaceBinder) ValidateWorkspace(nodeID, workspaceID string) error {
	if !b.IsAllowed(workspaceID, nodeID) {
		return sigilerr.New(sigilerr.CodeWorkspaceMembershipDenied, "node not allowed in workspace",
			sigilerr.Field("node_id", nodeID), sigilerr.FieldWorkspaceID(workspaceID))
	}
	return nil
}

// AllowedTools returns the tools a node is permitted to use in a workspace.
// Returns nil if the node does not match any rule for the workspace.
// Returns an empty slice if the node matches but has no tool restrictions
// (added via Bind without tool allowlists, meaning all tools are allowed).
// Output uses materialized node IDs in the form "node:<nodeID>:<tool>",
// never glob patterns.
func (b *WorkspaceBinder) AllowedTools(workspaceID, nodeID string) []string {
	ws := strings.TrimSpace(workspaceID)
	node := strings.TrimSpace(nodeID)
	if ws == "" || node == "" {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	var matched bool
	allowed := make(map[string]struct{})
	for _, rule := range b.rules[ws] {
		if !ruleMatches(rule.pattern, node) {
			continue
		}
		matched = true
		if len(rule.tools) == 0 {
			// Unrestricted Bind rule — all tools allowed, supersedes restrictions.
			return []string{}
		}
		for _, tool := range rule.tools {
			allowed[qualifiedTool(node, tool)] = struct{}{}
		}
	}

	if !matched {
		return nil
	}

	if len(allowed) == 0 {
		return []string{}
	}

	tools := make([]string, 0, len(allowed))
	for tool := range allowed {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools
}

// qualifiedTool returns a capability string in the form "node:<nodeID>:<tool>".
func qualifiedTool(nodeID, tool string) string {
	return "node:" + nodeID + ":" + tool
}

// ruleMatches checks if a node ID matches a glob pattern using path.Match.
// Patterns are validated at bind time, so ErrBadPattern here indicates a bug.
// path.Match is used instead of filepath.Match for platform-independent
// behavior since node IDs are identifiers, not file paths.
func ruleMatches(pattern, nodeID string) bool {
	matched, err := path.Match(pattern, nodeID)
	if err != nil {
		slog.Error("ruleMatches: invalid glob pattern stored", "pattern", pattern, "error", err)
		return false
	}
	return matched
}

// validatePatterns checks that all patterns are valid path.Match globs and
// do not contain the ':' separator used in capability strings.
func validatePatterns(patterns []string) error {
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return sigilerr.Errorf(sigilerr.CodeNodeBindInvalidInput, "invalid glob pattern %q: %w", p, err)
		}
		if strings.ContainsRune(p, ':') {
			return sigilerr.Errorf(sigilerr.CodeNodeBindInvalidInput, "pattern %q must not contain ':'", p)
		}
	}
	return nil
}

// deduplicatePatterns filters out patterns that already exist as Bind rules
// (nil tools) in the workspace. Must be called with b.mu held.
func (b *WorkspaceBinder) deduplicatePatterns(ws string, patterns []string) []string {
	existing := make(map[string]struct{})
	for _, r := range b.rules[ws] {
		if len(r.tools) == 0 {
			existing[r.pattern] = struct{}{}
		}
	}

	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if _, ok := existing[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}

func (b *WorkspaceBinder) checkLimits(ws string, count int) error {
	if _, exists := b.rules[ws]; !exists && len(b.rules) >= maxWorkspaces {
		return sigilerr.Errorf(sigilerr.CodeNodeBindLimitExceeded,
			"workspace limit exceeded (%d)", maxWorkspaces)
	}
	if len(b.rules[ws])+count > maxRulesPerWorkspace {
		return sigilerr.Errorf(sigilerr.CodeNodeBindLimitExceeded,
			"rule limit exceeded for workspace %q (%d)", ws, maxRulesPerWorkspace)
	}
	return nil
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}

	return out
}

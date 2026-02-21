// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type workspaceRule struct {
	pattern string
	tools   []string
}

// WorkspaceBinder binds node ID patterns and tool allowlists to workspaces.
type WorkspaceBinder struct {
	mu    sync.RWMutex
	rules map[string][]workspaceRule
}

func NewWorkspaceBinder() *WorkspaceBinder {
	return &WorkspaceBinder{
		rules: make(map[string][]workspaceRule),
	}
}

func (b *WorkspaceBinder) Bind(workspaceID string, nodePatterns []string) {
	ws := strings.TrimSpace(workspaceID)
	if ws == "" || len(nodePatterns) == 0 {
		return
	}

	normalized := normalizeStrings(nodePatterns)
	if len(normalized) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, pattern := range normalized {
		b.rules[ws] = append(b.rules[ws], workspaceRule{pattern: pattern})
	}
}

func (b *WorkspaceBinder) BindWithTools(workspaceID, nodePattern string, tools []string) {
	ws := strings.TrimSpace(workspaceID)
	pattern := strings.TrimSpace(nodePattern)
	if ws == "" || pattern == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.rules[ws] = append(b.rules[ws], workspaceRule{
		pattern: pattern,
		tools:   normalizeStrings(tools),
	})
}

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

func (b *WorkspaceBinder) AllowedTools(workspaceID, nodeID string) []string {
	ws := strings.TrimSpace(workspaceID)
	node := strings.TrimSpace(nodeID)
	if ws == "" || node == "" {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	allowed := make(map[string]struct{})
	for _, rule := range b.rules[ws] {
		if !ruleMatches(rule.pattern, node) {
			continue
		}
		for _, tool := range rule.tools {
			allowed["node:"+node+":"+tool] = struct{}{}
		}
	}

	if len(allowed) == 0 {
		return nil
	}

	tools := make([]string, 0, len(allowed))
	for tool := range allowed {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools
}

func ruleMatches(pattern, nodeID string) bool {
	matched, err := filepath.Match(pattern, nodeID)
	return err == nil && matched
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

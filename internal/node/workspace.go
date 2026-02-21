// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

// WorkspaceBinder binds node ID patterns and tool allowlists to workspaces.
type WorkspaceBinder struct{}

func NewWorkspaceBinder() *WorkspaceBinder {
	return &WorkspaceBinder{}
}

func (b *WorkspaceBinder) Bind(_ string, _ []string) {}

func (b *WorkspaceBinder) BindWithTools(_, _ string, _ []string) {}

func (b *WorkspaceBinder) IsAllowed(_, _ string) bool {
	return false
}

func (b *WorkspaceBinder) AllowedTools(_, _ string) []string {
	return nil
}

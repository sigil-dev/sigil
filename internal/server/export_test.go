// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import "context"

// ContextWithUser injects an AuthenticatedUser into a context for testing.
// This is exported only to _test packages via the export_test.go convention.
func ContextWithUser(ctx context.Context, user *AuthenticatedUser) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

// CheckWorkspaceMembership exposes checkWorkspaceMembership for direct unit testing.
func (s *Server) CheckWorkspaceMembership(ctx context.Context, workspaceID string) error {
	return s.checkWorkspaceMembership(ctx, workspaceID)
}

// RequireAdmin exposes requireAdmin for direct unit testing.
func (s *Server) RequireAdmin(ctx context.Context, permission, op string) error {
	return s.requireAdmin(ctx, permission, op)
}

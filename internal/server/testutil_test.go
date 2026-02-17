// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"fmt"

	"github.com/sigil-dev/sigil/internal/server"
)

// mustNewAuthenticatedUser is a test helper that panics if user creation fails.
func mustNewAuthenticatedUser(id, name string, permissions []string) *server.AuthenticatedUser {
	user, err := server.NewAuthenticatedUser(id, name, permissions)
	if err != nil {
		panic(fmt.Sprintf("failed to create authenticated user: %v", err))
	}
	return user
}

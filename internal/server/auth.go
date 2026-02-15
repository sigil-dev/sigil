// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// TokenValidator checks bearer tokens and returns the associated user.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*AuthenticatedUser, error)
}

// AuthenticatedUser represents a validated user from a bearer token.
type AuthenticatedUser struct {
	ID          string
	Name        string
	Permissions []string // capability patterns
}

// NewAuthenticatedUser creates an AuthenticatedUser with validation.
// Returns an error if id is empty, since all authenticated users must have an identity.
func NewAuthenticatedUser(id, name string, permissions []string) (*AuthenticatedUser, error) {
	if id == "" {
		return nil, sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "authenticated user ID must not be empty")
	}
	return &AuthenticatedUser{
		ID:          id,
		Name:        name,
		Permissions: permissions,
	}, nil
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const authUserKey contextKey = iota

// UserFromContext extracts the authenticated user from the request context.
// Returns nil if no user is authenticated (e.g., public endpoints or auth disabled).
func UserFromContext(ctx context.Context) *AuthenticatedUser {
	user, _ := ctx.Value(authUserKey).(*AuthenticatedUser)
	return user
}

// HasPermission checks whether the user has a permission matching the given pattern.
// Uses the same glob matching as capability enforcement: "admin:*" matches "admin:reload".
// Returns false if user is nil (unauthenticated / auth disabled).
func (u *AuthenticatedUser) HasPermission(required string) bool {
	if u == nil {
		return false
	}
	for _, p := range u.Permissions {
		if p == "*" || p == required {
			return true
		}
		// Simple prefix glob: "admin:*" matches any "admin:..." permission.
		if len(p) > 1 && p[len(p)-1] == '*' {
			prefix := p[:len(p)-1]
			if len(required) >= len(prefix) && required[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// defaultPublicPaths are paths that never require authentication.
var defaultPublicPaths = []string{"/health", "/openapi.json", "/openapi.yaml"}

// authMiddleware returns middleware that enforces bearer-token authentication.
// When validator is nil, auth is disabled and all requests pass through (dev mode).
func authMiddleware(validator TokenValidator) func(http.Handler) http.Handler {
	if validator == nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				slog.Debug("auth disabled: passing request through",
					"method", r.Method,
					"path", r.URL.Path,
				)
				next.ServeHTTP(w, r)
			})
		}
	}

	return NewAuthMiddleware(validator, defaultPublicPaths)
}

// NewAuthMiddleware creates an auth middleware function with explicit public paths.
// Exported for testing and composition.
func NewAuthMiddleware(validator TokenValidator, publicPaths []string) func(http.Handler) http.Handler {
	publicSet := make(map[string]struct{}, len(publicPaths))
	for _, p := range publicPaths {
		publicSet[p] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for public paths.
			if _, ok := publicSet[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}

			// Extract Authorization header.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAuthError(w, "authorization header required", http.StatusUnauthorized)
				return
			}

			// Must be "Bearer <token>" format.
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeAuthError(w, "authorization header must use Bearer scheme", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" {
				writeAuthError(w, "bearer token must not be empty", http.StatusUnauthorized)
				return
			}

			// Validate the token.
			user, err := validator.ValidateToken(r.Context(), token)
			if err != nil {
				slog.Debug("token validation failed",
					"path", r.URL.Path,
					"error", err,
				)
				if sigilerr.HasCode(err, sigilerr.CodeServerAuthForbidden) {
					writeAuthError(w, "forbidden", http.StatusForbidden)
					return
				}
				writeAuthError(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Inject user into context.
			ctx := context.WithValue(r.Context(), authUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authErrorBody is the JSON structure for auth error responses.
type authErrorBody struct {
	Error string `json:"error"`
}

func writeAuthError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(authErrorBody{Error: msg}); err != nil {
		slog.Warn("failed to write auth error response",
			"error", err,
			"status", status,
			"message", msg,
		)
	}
}

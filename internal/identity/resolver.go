// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package identity

import (
	"context"
	"errors"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Resolver maps platform-specific user identifiers to canonical Sigil users.
// It performs pure identity lookup without pairing or authorization checks.
// Channel-level authorization (pairing mode enforcement) is handled by
// ChannelRouter.AuthorizeInbound.
type Resolver struct {
	users store.UserStore
}

// NewResolver creates a Resolver backed by the given user store.
func NewResolver(users store.UserStore) *Resolver {
	return &Resolver{users: users}
}

// Resolve looks up the canonical user for a given channel type and platform user ID.
// Returns an error if no matching user is found or a backend failure occurs.
// Pairing/authorization checks are NOT performed here; callers should use
// ChannelRouter.AuthorizeInbound for mode-aware pairing enforcement.
func (r *Resolver) Resolve(ctx context.Context, channelType, platformUserID string) (*store.User, error) {
	user, err := r.users.GetByExternalID(ctx, channelType, platformUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, sigilerr.Wrap(
				err,
				CodeIdentityUserNotFound,
				"user not found",
				sigilerr.Field("platform", channelType),
				sigilerr.Field("platform_user_id", platformUserID),
			)
		}
		return nil, sigilerr.Wrap(
			err,
			CodeIdentityBackendFailure,
			"identity lookup failed",
			sigilerr.Field("platform", channelType),
			sigilerr.Field("platform_user_id", platformUserID),
		)
	}

	return user, nil
}

// CodeIdentityUserNotFound indicates that no user matches the given platform identity.
const CodeIdentityUserNotFound sigilerr.Code = "identity.user.not_found"

// CodeIdentityBackendFailure indicates an infrastructure error during identity lookup.
const CodeIdentityBackendFailure sigilerr.Code = "identity.backend.failure"

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
type Resolver struct {
	users    store.UserStore
	pairings store.PairingStore
}

// NewResolver creates a Resolver backed by the given stores.
func NewResolver(users store.UserStore, pairings store.PairingStore) *Resolver {
	return &Resolver{users: users, pairings: pairings}
}

// Resolve looks up the canonical user for a given channel type and platform user ID.
// Returns an error if no matching user is found.
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

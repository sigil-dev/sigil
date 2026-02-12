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
// It verifies that an active pairing exists for the channel before returning.
// Returns an error if no matching user is found or no active pairing exists.
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

	// Verify the user has an active pairing for this channel type.
	// We query by user ID (not channel ID) to avoid the semantic mismatch
	// between platformUserID and channelID — they are different identifiers.
	pairings, err := r.pairings.GetByUser(ctx, user.ID)
	if err != nil {
		return nil, sigilerr.Wrap(
			err,
			CodeIdentityBackendFailure,
			"pairing lookup failed",
			sigilerr.Field("platform", channelType),
			sigilerr.Field("user_id", user.ID),
		)
	}

	var found bool
	for _, p := range pairings {
		if p.ChannelType == channelType && p.Status == store.PairingStatusActive {
			found = true
			break
		}
	}
	if !found {
		return nil, sigilerr.New(
			CodeIdentityPairingRequired,
			"no active pairing for channel",
			sigilerr.Field("platform", channelType),
			sigilerr.Field("user_id", user.ID),
		)
	}

	return user, nil
}

// CodeIdentityUserNotFound indicates that no user matches the given platform identity.
const CodeIdentityUserNotFound sigilerr.Code = "identity.user.not_found"

// CodeIdentityBackendFailure indicates an infrastructure error during identity lookup.
const CodeIdentityBackendFailure sigilerr.Code = "identity.backend.failure"

// CodeIdentityPairingRequired indicates that no active pairing exists for the channel.
const CodeIdentityPairingRequired sigilerr.Code = "identity.pairing.required"

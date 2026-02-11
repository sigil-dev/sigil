// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// GatewayStore manages global (non-workspace) state.
type GatewayStore interface {
	Users() UserStore
	Pairings() PairingStore
	AuditLog() AuditStore
	Close() error
}

// UserStore manages user accounts.
type UserStore interface {
	Create(ctx context.Context, user *User) error
	Get(ctx context.Context, id string) (*User, error)
	GetByExternalID(ctx context.Context, provider, externalID string) (*User, error)
	Update(ctx context.Context, user *User) error
	List(ctx context.Context, opts ListOpts) ([]*User, error)
	Delete(ctx context.Context, id string) error
}

// PairingStore manages channel-user-workspace bindings.
type PairingStore interface {
	Create(ctx context.Context, pairing *Pairing) error
	GetByChannel(ctx context.Context, channelType, channelID string) (*Pairing, error)
	GetByUser(ctx context.Context, userID string) ([]*Pairing, error)
	Delete(ctx context.Context, id string) error
}

// AuditStore manages the audit log.
type AuditStore interface {
	Append(ctx context.Context, entry *AuditEntry) error
	Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
}

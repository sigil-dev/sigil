// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sigil-dev/sigil/internal/store"
)

// SessionManager provides high-level operations on agent sessions,
// delegating persistence to a store.SessionStore.
type SessionManager struct {
	ss store.SessionStore
}

// NewSessionManager returns a SessionManager backed by the given SessionStore.
func NewSessionManager(ss store.SessionStore) *SessionManager {
	return &SessionManager{ss: ss}
}

// Create initialises a new active session in the given workspace for the given user.
func (m *SessionManager) Create(ctx context.Context, workspaceID, userID string) (*store.Session, error) {
	now := time.Now()
	session := &store.Session{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		UserID:      userID,
		Status:      store.SessionStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := m.ss.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// Get retrieves a session by ID.
func (m *SessionManager) Get(ctx context.Context, id string) (*store.Session, error) {
	return m.ss.GetSession(ctx, id)
}

// List returns all sessions for the given workspace.
func (m *SessionManager) List(ctx context.Context, workspaceID string) ([]*store.Session, error) {
	return m.ss.ListSessions(ctx, workspaceID, store.ListOpts{})
}

// Archive marks a session as archived and updates its timestamp.
func (m *SessionManager) Archive(ctx context.Context, id string) error {
	session, err := m.ss.GetSession(ctx, id)
	if err != nil {
		return err
	}

	session.Status = store.SessionStatusArchived
	session.UpdatedAt = time.Now()

	return m.ss.UpdateSession(ctx, session)
}

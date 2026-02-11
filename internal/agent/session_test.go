// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSessionStore is an in-memory implementation of store.SessionStore for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*store.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*store.Session),
	}
}

func (m *mockSessionStore) CreateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; exists {
		return store.ErrConflict
	}

	// Store a copy to avoid aliasing.
	s := *session
	m.sessions[session.ID] = &s
	return nil
}

func (m *mockSessionStore) GetSession(_ context.Context, id string) (*store.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	copy := *s
	return &copy, nil
}

func (m *mockSessionStore) UpdateSession(_ context.Context, session *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return store.ErrNotFound
	}

	s := *session
	m.sessions[session.ID] = &s
	return nil
}

func (m *mockSessionStore) ListSessions(_ context.Context, workspaceID string, opts store.ListOpts) ([]*store.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*store.Session
	for _, s := range m.sessions {
		if s.WorkspaceID == workspaceID {
			copy := *s
			result = append(result, &copy)
		}
	}

	// Apply offset/limit.
	if opts.Offset > 0 {
		if opts.Offset >= len(result) {
			return nil, nil
		}
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

func (m *mockSessionStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[id]; !exists {
		return store.ErrNotFound
	}

	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) AppendMessage(_ context.Context, _ string, _ *store.Message) error {
	return nil
}

func (m *mockSessionStore) GetActiveWindow(_ context.Context, _ string, _ int) ([]*store.Message, error) {
	return nil, nil
}

func TestSessionManager_CreateAndGet(t *testing.T) {
	ms := newMockSessionStore()
	sm := agent.NewSessionManager(ms)

	ctx := context.Background()
	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify generated fields.
	assert.NotEmpty(t, session.ID, "ID should be a generated UUID")
	assert.Equal(t, "ws-1", session.WorkspaceID)
	assert.Equal(t, "user-1", session.UserID)
	assert.Equal(t, store.SessionStatusActive, session.Status)
	assert.False(t, session.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, session.UpdatedAt.IsZero(), "UpdatedAt should be set")
	assert.Equal(t, session.CreatedAt, session.UpdatedAt, "timestamps should match at creation")

	// Get by ID should return the same session.
	got, err := sm.Get(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.WorkspaceID, got.WorkspaceID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, session.Status, got.Status)
}

func TestSessionManager_ListByWorkspace(t *testing.T) {
	ms := newMockSessionStore()
	sm := agent.NewSessionManager(ms)

	ctx := context.Background()

	// Create sessions across two workspaces.
	s1, err := sm.Create(ctx, "ws-a", "user-1")
	require.NoError(t, err)

	_, err = sm.Create(ctx, "ws-b", "user-2")
	require.NoError(t, err)

	s3, err := sm.Create(ctx, "ws-a", "user-3")
	require.NoError(t, err)

	// List workspace A — should return exactly 2.
	list, err := sm.List(ctx, "ws-a")
	require.NoError(t, err)
	assert.Len(t, list, 2)

	ids := make(map[string]bool)
	for _, s := range list {
		ids[s.ID] = true
	}
	assert.True(t, ids[s1.ID], "should contain first session")
	assert.True(t, ids[s3.ID], "should contain third session")

	// List workspace B — should return exactly 1.
	list, err = sm.List(ctx, "ws-b")
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// List nonexistent workspace — should return empty.
	list, err = sm.List(ctx, "ws-nonexistent")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestSessionManager_Archive(t *testing.T) {
	ms := newMockSessionStore()
	sm := agent.NewSessionManager(ms)

	ctx := context.Background()

	session, err := sm.Create(ctx, "ws-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, store.SessionStatusActive, session.Status)

	// Small delay so UpdatedAt differs.
	time.Sleep(time.Millisecond)

	err = sm.Archive(ctx, session.ID)
	require.NoError(t, err)

	got, err := sm.Get(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, store.SessionStatusArchived, got.Status)
	assert.True(t, got.UpdatedAt.After(got.CreatedAt), "UpdatedAt should be after CreatedAt")
}

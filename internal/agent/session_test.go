// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

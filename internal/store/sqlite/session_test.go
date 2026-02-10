// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore_CRUD(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	session := &store.Session{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   time.Now().Truncate(time.Millisecond),
		UpdatedAt:   time.Now().Truncate(time.Millisecond),
	}

	// Create
	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Get
	got, err := ss.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.WorkspaceID, got.WorkspaceID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, store.SessionStatusActive, got.Status)

	// Update
	session.Status = store.SessionStatusPaused
	session.Summary = "Updated summary"
	err = ss.UpdateSession(ctx, session)
	require.NoError(t, err)

	got, err = ss.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, store.SessionStatusPaused, got.Status)
	assert.Equal(t, "Updated summary", got.Summary)

	// List
	sessions, err := ss.ListSessions(ctx, "ws-1", store.ListOpts{})
	require.NoError(t, err)
	assert.Len(t, sessions, 1)

	// Delete
	err = ss.DeleteSession(ctx, "sess-1")
	require.NoError(t, err)

	_, err = ss.GetSession(ctx, "sess-1")
	assert.Error(t, err)
}

func TestSessionStore_ActiveWindow(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-window")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create session first
	err = ss.CreateSession(ctx, &store.Session{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	require.NoError(t, err)

	// Append messages
	for i := 0; i < 5; i++ {
		msg := &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		err = ss.AppendMessage(ctx, "sess-1", msg)
		require.NoError(t, err)
	}

	// Get last 3 messages
	msgs, err := ss.GetActiveWindow(ctx, "sess-1", 3)
	require.NoError(t, err)
	assert.Len(t, msgs, 3)
	// Should be most recent messages, ordered chronologically
	assert.Equal(t, "Message 2", msgs[0].Content)
	assert.Equal(t, "Message 4", msgs[2].Content)
}

func TestSessionStore_GetNonExistent(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-noent")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	_, err = ss.GetSession(ctx, "nonexistent")
	assert.Error(t, err)
}

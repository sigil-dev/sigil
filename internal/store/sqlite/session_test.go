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
	assert.ErrorIs(t, err, store.ErrNotFound)
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
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestSessionStore_BudgetPersistence(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-budget")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create session with budget fields
	session := &store.Session{
		ID:          "sess-budget",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		ToolBudget: store.ToolBudget{
			MaxCallsPerTurn:    5,
			MaxCallsPerSession: 100,
			Used:               42,
		},
		TokenBudget: store.TokenBudget{
			MaxPerSession: 10000,
			MaxPerHour:    50000,
			MaxPerDay:     200000,
			UsedSession:   5000,
			UsedHour:      25000,
			UsedDay:       100000,
		},
		CreatedAt: time.Now().Truncate(time.Millisecond),
		UpdatedAt: time.Now().Truncate(time.Millisecond),
	}

	// Create
	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Get and verify budget fields
	got, err := ss.GetSession(ctx, "sess-budget")
	require.NoError(t, err)
	assert.Equal(t, 5, got.ToolBudget.MaxCallsPerTurn, "ToolBudget.MaxCallsPerTurn should persist")
	assert.Equal(t, 100, got.ToolBudget.MaxCallsPerSession, "ToolBudget.MaxCallsPerSession should persist")
	assert.Equal(t, 42, got.ToolBudget.Used, "ToolBudget.Used should persist")
	assert.Equal(t, 10000, got.TokenBudget.MaxPerSession, "TokenBudget.MaxPerSession should persist")
	assert.Equal(t, 50000, got.TokenBudget.MaxPerHour, "TokenBudget.MaxPerHour should persist")
	assert.Equal(t, 200000, got.TokenBudget.MaxPerDay, "TokenBudget.MaxPerDay should persist")
	assert.Equal(t, 5000, got.TokenBudget.UsedSession, "TokenBudget.UsedSession should persist")
	assert.Equal(t, 25000, got.TokenBudget.UsedHour, "TokenBudget.UsedHour should persist")
	assert.Equal(t, 100000, got.TokenBudget.UsedDay, "TokenBudget.UsedDay should persist")
}

func TestSessionStore_BudgetZeroValues(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-budget-zero")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create session with zero budget values (explicitly set to 0)
	session := &store.Session{
		ID:          "sess-zero",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		ToolBudget: store.ToolBudget{
			MaxCallsPerTurn:    0,
			MaxCallsPerSession: 0,
			Used:               0,
		},
		TokenBudget: store.TokenBudget{
			MaxPerSession: 0,
			MaxPerHour:    0,
			MaxPerDay:     0,
			UsedSession:   0,
			UsedHour:      0,
			UsedDay:       0,
		},
		CreatedAt: time.Now().Truncate(time.Millisecond),
		UpdatedAt: time.Now().Truncate(time.Millisecond),
	}

	// Create
	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Get and verify zero values are preserved
	got, err := ss.GetSession(ctx, "sess-zero")
	require.NoError(t, err)
	assert.Equal(t, 0, got.ToolBudget.MaxCallsPerTurn, "Zero ToolBudget.MaxCallsPerTurn should persist")
	assert.Equal(t, 0, got.ToolBudget.MaxCallsPerSession, "Zero ToolBudget.MaxCallsPerSession should persist")
	assert.Equal(t, 0, got.ToolBudget.Used, "Zero ToolBudget.Used should persist")
	assert.Equal(t, 0, got.TokenBudget.MaxPerSession, "Zero TokenBudget.MaxPerSession should persist")
	assert.Equal(t, 0, got.TokenBudget.MaxPerHour, "Zero TokenBudget.MaxPerHour should persist")
	assert.Equal(t, 0, got.TokenBudget.MaxPerDay, "Zero TokenBudget.MaxPerDay should persist")
	assert.Equal(t, 0, got.TokenBudget.UsedSession, "Zero TokenBudget.UsedSession should persist")
	assert.Equal(t, 0, got.TokenBudget.UsedHour, "Zero TokenBudget.UsedHour should persist")
	assert.Equal(t, 0, got.TokenBudget.UsedDay, "Zero TokenBudget.UsedDay should persist")
}

func TestSessionStore_BudgetUpdate(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-budget-update")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create session with initial budget
	session := &store.Session{
		ID:          "sess-update",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		ToolBudget: store.ToolBudget{
			MaxCallsPerTurn:    5,
			MaxCallsPerSession: 100,
			Used:               10,
		},
		TokenBudget: store.TokenBudget{
			MaxPerSession: 10000,
			MaxPerHour:    50000,
			MaxPerDay:     200000,
			UsedSession:   1000,
			UsedHour:      5000,
			UsedDay:       20000,
		},
		CreatedAt: time.Now().Truncate(time.Millisecond),
		UpdatedAt: time.Now().Truncate(time.Millisecond),
	}

	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Update budget values
	session.ToolBudget.Used = 50
	session.ToolBudget.MaxCallsPerSession = 200
	session.TokenBudget.UsedSession = 8000
	session.TokenBudget.UsedHour = 45000
	session.TokenBudget.MaxPerDay = 300000

	err = ss.UpdateSession(ctx, session)
	require.NoError(t, err)

	// Get and verify updated values
	got, err := ss.GetSession(ctx, "sess-update")
	require.NoError(t, err)
	assert.Equal(t, 50, got.ToolBudget.Used, "Updated ToolBudget.Used should persist")
	assert.Equal(t, 200, got.ToolBudget.MaxCallsPerSession, "Updated ToolBudget.MaxCallsPerSession should persist")
	assert.Equal(t, 5, got.ToolBudget.MaxCallsPerTurn, "Unchanged ToolBudget.MaxCallsPerTurn should persist")
	assert.Equal(t, 8000, got.TokenBudget.UsedSession, "Updated TokenBudget.UsedSession should persist")
	assert.Equal(t, 45000, got.TokenBudget.UsedHour, "Updated TokenBudget.UsedHour should persist")
	assert.Equal(t, 300000, got.TokenBudget.MaxPerDay, "Updated TokenBudget.MaxPerDay should persist")
	assert.Equal(t, 10000, got.TokenBudget.MaxPerSession, "Unchanged TokenBudget.MaxPerSession should persist")
	assert.Equal(t, 20000, got.TokenBudget.UsedDay, "Unchanged TokenBudget.UsedDay should persist")
}

func TestSessionStore_BudgetListSessions(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-budget-list")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create sessions with different budget values
	for i := 0; i < 3; i++ {
		session := &store.Session{
			ID:          fmt.Sprintf("sess-list-%d", i),
			WorkspaceID: "ws-1",
			UserID:      "usr-1",
			Status:      store.SessionStatusActive,
			ToolBudget: store.ToolBudget{
				MaxCallsPerTurn:    i + 1,
				MaxCallsPerSession: (i + 1) * 10,
				Used:               i * 5,
			},
			TokenBudget: store.TokenBudget{
				MaxPerSession: (i + 1) * 1000,
				MaxPerHour:    (i + 1) * 5000,
				MaxPerDay:     (i + 1) * 20000,
				UsedSession:   i * 500,
				UsedHour:      i * 2500,
				UsedDay:       i * 10000,
			},
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			UpdatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		err = ss.CreateSession(ctx, session)
		require.NoError(t, err)
	}

	// List sessions and verify budget fields
	sessions, err := ss.ListSessions(ctx, "ws-1", store.ListOpts{})
	require.NoError(t, err)
	require.Len(t, sessions, 3)

	// Sessions are returned in descending order by created_at
	// So sess-list-2 should be first
	assert.Equal(t, 3, sessions[0].ToolBudget.MaxCallsPerTurn)
	assert.Equal(t, 30, sessions[0].ToolBudget.MaxCallsPerSession)
	assert.Equal(t, 10, sessions[0].ToolBudget.Used)
	assert.Equal(t, 3000, sessions[0].TokenBudget.MaxPerSession)
	assert.Equal(t, 15000, sessions[0].TokenBudget.MaxPerHour)
	assert.Equal(t, 60000, sessions[0].TokenBudget.MaxPerDay)
	assert.Equal(t, 1000, sessions[0].TokenBudget.UsedSession)
	assert.Equal(t, 5000, sessions[0].TokenBudget.UsedHour)
	assert.Equal(t, 20000, sessions[0].TokenBudget.UsedDay)
}

// TestParseTime_ErrorPropagation verifies that malformed timestamps cause errors
// instead of being silently ignored.
func TestParseTime_ErrorPropagation(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-parse-error")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	// Create a valid session
	session := &store.Session{
		ID:          "sess-parse-test",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Get should succeed with valid data
	got, err := ss.GetSession(ctx, "sess-parse-test")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
}

// TestParseTime_MalformedTimestamps verifies that ParseTime returns errors
// for invalid timestamp strings instead of silently returning zero time.
func TestParseTime_MalformedTimestamps(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"not a timestamp", "not-a-timestamp", true},
		{"invalid date", "2024-13-45T00:00:00Z", true},
		{"invalid format", "2024/01/01", true},
		{"empty string", "", false}, // Empty string returns zero time without error
		{"valid RFC3339", "2024-01-15T10:30:00Z", false},
		{"valid RFC3339Nano", "2024-01-15T10:30:00.123456789Z", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sqlite.ParseTime(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "ParseTime should return error for invalid input: %q", tt.input)
				assert.Contains(t, err.Error(), "parsing timestamp", "Error should contain context about parsing timestamp")
				assert.True(t, result.IsZero(), "Result should be zero time when error occurs")
			} else {
				assert.NoError(t, err, "ParseTime should not error for valid input: %q", tt.input)
				if tt.input == "" {
					assert.True(t, result.IsZero(), "Empty string should return zero time")
				} else {
					assert.False(t, result.IsZero(), "Valid timestamp should return non-zero time")
				}
			}
		})
	}
}

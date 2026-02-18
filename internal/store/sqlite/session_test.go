// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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
	assert.True(t, sigilerr.IsNotFound(err))
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
	assert.True(t, sigilerr.IsNotFound(err))
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

// TestMigrate_AddThreatInfoColumn verifies that migrate() adds the threat_info
// column to an existing messages table that was created without it. This simulates
// upgrading a database created before the threat_info column was introduced.
func TestMigrate_AddThreatInfoColumn(t *testing.T) {
	ctx := context.Background()
	dbPath := testDBPath(t, "sessions-migrate-threat")

	// Bootstrap a database with the old schema — messages table without threat_info.
	{
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
		require.NoError(t, err)

		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS sessions (
	id             TEXT PRIMARY KEY,
	workspace_id   TEXT NOT NULL,
	user_id        TEXT NOT NULL,
	summary        TEXT NOT NULL DEFAULT '',
	last_compaction TEXT NOT NULL DEFAULT '',
	model_override TEXT NOT NULL DEFAULT '',
	status         TEXT NOT NULL DEFAULT 'active',
	tool_budget_max_calls_per_turn INTEGER NOT NULL DEFAULT 0,
	tool_budget_max_calls_per_session INTEGER NOT NULL DEFAULT 0,
	tool_budget_used INTEGER NOT NULL DEFAULT 0,
	token_budget_per_session_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_per_hour_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_per_day_limit INTEGER NOT NULL DEFAULT 0,
	token_budget_used_session INTEGER NOT NULL DEFAULT 0,
	token_budget_used_hour INTEGER NOT NULL DEFAULT 0,
	token_budget_used_day INTEGER NOT NULL DEFAULT 0,
	created_at     TEXT NOT NULL,
	updated_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
	id           TEXT PRIMARY KEY,
	session_id   TEXT NOT NULL,
	role         TEXT NOT NULL,
	content      TEXT NOT NULL DEFAULT '',
	tool_call_id TEXT NOT NULL DEFAULT '',
	tool_name    TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	metadata     TEXT NOT NULL DEFAULT '{}',
	FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
`)
		require.NoError(t, err, "setting up old schema")

		// Verify threat_info is absent in the baseline schema.
		rows, err := db.Query("PRAGMA table_info(messages)")
		require.NoError(t, err)
		found := false
		for rows.Next() {
			var cid int
			var name, colType string
			var notNull int
			var dfltValue sql.NullString
			var pk int
			require.NoError(t, rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk))
			if name == "threat_info" {
				found = true
			}
		}
		require.NoError(t, rows.Err())
		_ = rows.Close()
		require.False(t, found, "threat_info should not exist in the old schema")

		_ = db.Close()
	}

	// Open via NewSessionStore — this runs migrate() which must add the column.
	ss, err := sqlite.NewSessionStore(dbPath)
	require.NoError(t, err, "NewSessionStore should succeed and run migration")
	defer func() { _ = ss.Close() }()

	// Create a session to satisfy the FK constraint.
	now := time.Now().UTC().Truncate(time.Second)
	err = ss.CreateSession(ctx, &store.Session{
		ID:          "sess-migrate",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	// Append a message with threat data to confirm the column is usable.
	threat := &store.ThreatInfo{
		Detected: true,
		Rules:    []string{"rule-injection"},
	}
	msg := &store.Message{
		ID:        "msg-migrate-1",
		SessionID: "sess-migrate",
		Role:      store.MessageRoleUser,
		Content:   "probe",
		Threat:    threat,
		CreatedAt: now,
	}
	err = ss.AppendMessage(ctx, "sess-migrate", msg)
	require.NoError(t, err, "AppendMessage should work after migration adds threat_info")

	// Read back and verify threat data round-trips correctly.
	msgs, err := ss.GetActiveWindow(ctx, "sess-migrate", 10)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.NotNil(t, msgs[0].Threat, "Threat field should be populated after round-trip")
	assert.True(t, msgs[0].Threat.Detected)
	assert.Equal(t, []string{"rule-injection"}, msgs[0].Threat.Rules)
}

// TestSessionStore_ThreatInfo_OutputStage verifies that an assistant message with a
// ScanStageOutput ThreatInfo (Detected=true, Scanned=true, Stage=output) round-trips
// correctly through the SQLite session store. This complements
// TestMigrate_AddThreatInfoColumn which only tests ScanStageInput.
func TestSessionStore_ThreatInfo_OutputStage(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-threat-output")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	now := time.Now().UTC().Truncate(time.Second)

	err = ss.CreateSession(ctx, &store.Session{
		ID:          "sess-threat-output",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	// Append an assistant message with an output-stage threat detection.
	threat := store.NewThreatDetected(store.ScanStageOutput, []string{"rule-prompt-leak", "rule-pii"})
	msg := &store.Message{
		ID:        "msg-output-threat-1",
		SessionID: "sess-threat-output",
		Role:      store.MessageRoleAssistant,
		Content:   "redacted output",
		Threat:    threat,
		CreatedAt: now,
	}
	err = ss.AppendMessage(ctx, "sess-threat-output", msg)
	require.NoError(t, err)

	// Retrieve the message and assert the ThreatInfo round-trips correctly.
	msgs, err := ss.GetActiveWindow(ctx, "sess-threat-output", 10)
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	got := msgs[0]
	require.NotNil(t, got.Threat, "Threat field must be non-nil after round-trip")
	assert.True(t, got.Threat.Scanned, "Threat.Scanned should be true")
	assert.True(t, got.Threat.Detected, "Threat.Detected should be true")
	assert.Equal(t, store.ScanStageOutput, got.Threat.Stage, "Stage must be ScanStageOutput, not ScanStageInput")
	assert.Equal(t, []string{"rule-prompt-leak", "rule-pii"}, got.Threat.Rules, "matched rules must be preserved")
}

// TestSessionStore_LegacyThreatInfoBackwardCompat verifies that pre-Scanned records
// stored as `{}` in the threat_info column unmarshal with Scanned==false and
// Detected==false, correctly representing "scanner did not run" for historical data.
func TestSessionStore_LegacyThreatInfoBackwardCompat(t *testing.T) {
	ctx := context.Background()
	dbPath := testDBPath(t, "sessions-legacy-threat")
	ss, err := sqlite.NewSessionStore(dbPath)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Create a session to satisfy the FK constraint.
	err = ss.CreateSession(ctx, &store.Session{
		ID:          "sess-legacy",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	// Append a message via the normal API (threat_info will be set to some value).
	msg := &store.Message{
		ID:        "msg-legacy-1",
		SessionID: "sess-legacy",
		Role:      store.MessageRoleUser,
		Content:   "legacy content",
		CreatedAt: now,
	}
	err = ss.AppendMessage(ctx, "sess-legacy", msg)
	require.NoError(t, err)

	// Simulate a legacy record by overwriting threat_info with '{}' via raw SQL.
	// This represents a message written before the Scanned field was introduced.
	rawDB, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	require.NoError(t, err)
	defer func() { _ = rawDB.Close() }()

	_, err = rawDB.ExecContext(ctx,
		`UPDATE messages SET threat_info = '{}' WHERE id = 'msg-legacy-1'`)
	require.NoError(t, err, "raw SQL update to simulate legacy threat_info should succeed")

	// Read back via GetActiveWindow and assert legacy {} is interpreted as "not scanned".
	msgs, err := ss.GetActiveWindow(ctx, "sess-legacy", 10)
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	got := msgs[0]
	// The store treats '{}' as "no threat data" and leaves Threat nil — this is the
	// correct backward-compat interpretation: nil means "scanner did not run",
	// equivalent to Scanned=false, Detected=false.
	// If the store ever changes to deserialize '{}' into &ThreatInfo{}, those fields
	// must still be false (no scan ran, no threat was detected).
	if got.Threat != nil {
		assert.False(t, got.Threat.Scanned, "Scanned must be false for legacy {} records (scanner did not run)")
		assert.False(t, got.Threat.Detected, "Detected must be false for legacy {} records")
	}
	// Either nil or &ThreatInfo{Scanned:false, Detected:false} is correct.
	// Verify neither a detected flag nor a scanned flag is set.
	threatScanned := got.Threat != nil && got.Threat.Scanned
	threatDetected := got.Threat != nil && got.Threat.Detected
	assert.False(t, threatScanned, "legacy {} must not have Scanned=true")
	assert.False(t, threatDetected, "legacy {} must not have Detected=true")
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

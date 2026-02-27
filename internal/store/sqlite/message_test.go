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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageStore_AppendAndSearch(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	msgs := []struct {
		id      string
		content string
	}{
		{"msg-1", "The Kubernetes cluster is running smoothly"},
		{"msg-2", "We need to update the Terraform configuration"},
		{"msg-3", "The weather is nice today"},
	}

	for _, m := range msgs {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        m.id,
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   m.content,
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	results, err := ms.Search(ctx, "ws-1", "Kubernetes", store.SearchOpts{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Contains(t, results[0].Content, "Kubernetes")

	results, err = ms.Search(ctx, "ws-1", "Python", store.SearchOpts{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestMessageStore_Count(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-count")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	for i := 0; i < 3; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	count, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMessageStore_DeleteByIDs(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-delete-by-ids")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		})
		require.NoError(t, err)
	}

	err = ms.Append(ctx, "ws-2", &store.Message{
		ID:        "other-ws-msg",
		SessionID: "sess-2",
		Role:      store.MessageRoleUser,
		Content:   "Other workspace message",
		CreatedAt: base.Add(10 * time.Second),
	})
	require.NoError(t, err)

	deleted, err := ms.DeleteByIDs(ctx, "ws-1", []string{"msg-0", "msg-2", "missing-id"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	count, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	otherCount, err := ms.Count(ctx, "ws-2")
	require.NoError(t, err)
	assert.Equal(t, int64(1), otherCount, "deletion must stay within workspace")

	deleted, err = ms.DeleteByIDs(ctx, "ws-1", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestMessageStore_DeleteByIDs_LargeBatch(t *testing.T) {
	// Verify that DeleteByIDs correctly handles batches exceeding SQLite's
	// 999-variable limit by splitting into multiple statements and accumulating
	// the total deleted count across all batches.
	const count = 1001
	ctx := context.Background()
	db := testDBPath(t, "messages-delete-large-batch")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := make([]string, count)
	for i := 0; i < count; i++ {
		ids[i] = fmt.Sprintf("msg-%d", i)
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        ids[i],
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		})
		require.NoError(t, err)
	}

	n, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	require.Equal(t, int64(count), n)

	deleted, err := ms.DeleteByIDs(ctx, "ws-1", ids)
	require.NoError(t, err)
	assert.Equal(t, int64(count), deleted)

	remaining, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(0), remaining)
}

func TestMessageStore_Trim(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-trim")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	for i := 0; i < 10; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		})
		require.NoError(t, err)
	}

	trimmed, err := ms.Trim(ctx, "ws-1", 3)
	require.NoError(t, err)
	assert.Equal(t, int64(7), trimmed)

	count, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMessageStore_GetRange(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-range")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		})
		require.NoError(t, err)
	}

	from := base
	to := base.Add(3 * time.Hour)
	results, err := ms.GetRange(ctx, "ws-1", from, to)
	require.NoError(t, err)
	assert.Len(t, results, 3) // messages 0, 1, 2
}

func TestMessageStore_GetRange_WithLimit(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-range-limit")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		})
		require.NoError(t, err)
	}

	from := base
	to := base.Add(5 * time.Hour)

	t.Run("positive_limit", func(t *testing.T) {
		// limit=2 should return only the 2 oldest.
		results, err := ms.GetRange(ctx, "ws-1", from, to, 2)
		require.NoError(t, err)
		require.Len(t, results, 2)
		assert.Equal(t, "msg-0", results[0].ID)
		assert.Equal(t, "msg-1", results[1].ID)
	})

	t.Run("zero_limit_means_unlimited", func(t *testing.T) {
		// limit=0 must return all messages, not zero results.
		results, err := ms.GetRange(ctx, "ws-1", from, to, 0)
		require.NoError(t, err)
		assert.Len(t, results, 5, "limit=0 should return all messages (unlimited behavior)")
	})
}

// TestMessageStore_Search_InjectionTests verifies that FTS5 query injection
// attempts are properly sanitized and do not alter query behavior.
// The sanitization works by wrapping the entire query in double quotes,
// treating it as a single phrase and preventing FTS5 operators from being
// interpreted.
func TestMessageStore_Search_InjectionTests(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-injection")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	// Set up test messages with content that could trigger injection
	msgs := []struct {
		id      string
		content string
	}{
		{"msg-1", "The Kubernetes cluster is running smoothly"},
		{"msg-2", "We need to update the Terraform configuration"},
		{"msg-3", "The weather is nice today"},
		{"msg-4", "Database OR cache layer needs tuning"},
		{"msg-5", "Update NOT required for this release"},
		{"msg-6", "Search with asterisk* symbol"},
		{"msg-7", "The " + `"quoted"` + " text appears here"},
		{"msg-8", "Use parentheses (carefully) in your queries"},
		{"msg-9", "The cluster:main is running"},
	}

	for _, m := range msgs {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        m.id,
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   m.content,
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		query         string
		expectedCount int
		description   string
	}{
		{
			name:          "OR_injection_prevented",
			query:         "Kubernetes OR Terraform",
			expectedCount: 0, // Searching for literal phrase "Kubernetes OR Terraform" - not OR logic
			description:   "OR operator should be treated as literal text, not boolean",
		},
		{
			name:          "NOT_injection_prevented",
			query:         "Update NOT required",
			expectedCount: 1, // Finds msg-5 which contains "Update NOT required for this release"
			description:   "NOT operator should be treated as literal text, not boolean",
		},
		{
			name:          "NEAR_injection_prevented",
			query:         "running NEAR/5 smoothly",
			expectedCount: 0, // Searching for literal phrase, not NEAR proximity
			description:   "NEAR operator should be treated as literal text, not proximity",
		},
		{
			name:          "column_filter_injection_prevented",
			query:         "cluster:main",
			expectedCount: 1, // Tokenizer splits "cluster:main" into "cluster" and "main" tokens
			description:   "Column filter should be treated as literal text (not as column:term filter)",
		},
		{
			name:          "quote_injection_prevented",
			query:         `"quoted"`,
			expectedCount: 1, // Finds msg-7 with escaped quotes
			description:   "Quote injection should be safely escaped",
		},
		{
			name:          "wildcard_injection_prevented",
			query:         `asterisk*`,
			expectedCount: 1, // Finds msg-6 with literal asterisk
			description:   "Wildcard should be treated as literal text",
		},
		{
			name:          "parentheses_injection_prevented",
			query:         `(carefully)`,
			expectedCount: 1, // Finds msg-8 with literal parentheses
			description:   "Parentheses should be treated as literal text",
		},
		{
			name:          "hyphen_injection_prevented",
			query:         `cluster-smoothly`,
			expectedCount: 0, // No message has this exact hyphenated phrase
			description:   "Hyphen should be treated as literal text",
		},
		{
			name:          "safe_term_still_works",
			query:         `Kubernetes`,
			expectedCount: 1, // Normal search should still work
			description:   "Normal search without metacharacters should work",
		},
		{
			name:          "multiple_words_as_phrase",
			query:         `Kubernetes cluster`,
			expectedCount: 1, // Finds msg-1 with exact phrase
			description:   "Multiple words should be treated as a phrase",
		},
		{
			name:          "injection_with_quotes_and_OR",
			query:         `"Kubernetes" OR "Terraform"`,
			expectedCount: 0, // Searching for literal string with quotes and OR
			description:   "Complex injection with quotes and OR should be safe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := ms.Search(ctx, "ws-1", tt.query, store.SearchOpts{Limit: 10})
			require.NoError(t, err, "Search should not error for query: %s", tt.query)
			assert.Len(t, results, tt.expectedCount, "%s: query=%q", tt.description, tt.query)
		})
	}
}

// TestMessageStore_Search_WorkspaceIsolation verifies that search respects workspace boundaries.
func TestMessageStore_Search_WorkspaceIsolation(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-workspace")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer func() { _ = ms.Close() }()

	// Add message to ws-1
	err = ms.Append(ctx, "ws-1", &store.Message{
		ID:        "msg-ws1",
		SessionID: "sess-1",
		Role:      store.MessageRoleUser,
		Content:   "Sensitive information in workspace 1",
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Add message to ws-2
	err = ms.Append(ctx, "ws-2", &store.Message{
		ID:        "msg-ws2",
		SessionID: "sess-2",
		Role:      store.MessageRoleUser,
		Content:   "Sensitive information in workspace 2",
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Search ws-1 should only return ws-1 message
	results, err := ms.Search(ctx, "ws-1", "Sensitive", store.SearchOpts{})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "msg-ws1", results[0].ID)

	// Search ws-2 should only return ws-2 message
	results, err = ms.Search(ctx, "ws-2", "Sensitive", store.SearchOpts{})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "msg-ws2", results[0].ID)
}

// TestMigrate_MemoryMessagesOriginColumn verifies that migrateMessages() adds the
// origin column to an existing memory_messages table that was created without it.
// This simulates upgrading a database created before the origin column was introduced.
func TestMigrate_MemoryMessagesOriginColumn(t *testing.T) {
	ctx := context.Background()
	dbPath := testDBPath(t, "messages-migrate-origin")

	// Bootstrap a database with the old memory_messages schema — without origin.
	{
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
		require.NoError(t, err)

		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS memory_messages (
	rowid        INTEGER PRIMARY KEY AUTOINCREMENT,
	id           TEXT UNIQUE NOT NULL,
	workspace_id TEXT NOT NULL,
	session_id   TEXT NOT NULL,
	role         TEXT NOT NULL,
	content      TEXT NOT NULL DEFAULT '',
	tool_call_id TEXT NOT NULL DEFAULT '',
	tool_name    TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	metadata     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_memory_messages_workspace ON memory_messages(workspace_id);
CREATE INDEX IF NOT EXISTS idx_memory_messages_workspace_created ON memory_messages(workspace_id, created_at);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_messages_fts USING fts5(
	content,
	content='memory_messages',
	content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS memory_messages_ai AFTER INSERT ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

CREATE TRIGGER IF NOT EXISTS memory_messages_ad AFTER DELETE ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(memory_messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;

CREATE TRIGGER IF NOT EXISTS memory_messages_au AFTER UPDATE ON memory_messages BEGIN
	INSERT INTO memory_messages_fts(memory_messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
	INSERT INTO memory_messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;
`)
		require.NoError(t, err, "setting up old schema")

		// Verify origin column is absent in the baseline schema.
		rows, err := db.Query("PRAGMA table_info(memory_messages)")
		require.NoError(t, err)
		found := false
		for rows.Next() {
			var cid int
			var name, colType string
			var notNull int
			var dfltValue sql.NullString
			var pk int
			require.NoError(t, rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk))
			if name == "origin" {
				found = true
			}
		}
		require.NoError(t, rows.Err())
		_ = rows.Close()
		require.False(t, found, "origin should not exist in the old schema")

		_ = db.Close()
	}

	// Open via NewMessageStore — this runs migrateMessages() which must add the column.
	ms, err := sqlite.NewMessageStore(dbPath)
	require.NoError(t, err, "NewMessageStore should succeed and run migration")
	defer func() { _ = ms.Close() }()

	// Append a message with an origin value to confirm the column is usable.
	now := time.Now().UTC().Truncate(time.Second)
	msg := &store.Message{
		ID:        "msg-migrate-origin-1",
		SessionID: "sess-migrate",
		Role:      store.MessageRoleUser,
		Content:   "probe message for origin migration",
		Origin:    "user_input",
		CreatedAt: now,
	}
	err = ms.Append(ctx, "ws-migrate", msg)
	require.NoError(t, err, "Append should work after migration adds origin column")

	// Read back via Search and verify the origin round-trips correctly.
	results, err := ms.Search(ctx, "ws-migrate", "probe", store.SearchOpts{Limit: 10})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "user_input", results[0].Origin, "Origin should round-trip through storage")
}

func TestMessageStore_GetOldest(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		setup      func(ms *sqlite.MessageStore)
		workspace  string
		n          int
		wantLen    int
		wantFirst  string // expected ID of first returned message
		wantLast   string // expected ID of last returned message
	}{
		{
			name: "ordering_oldest_first",
			setup: func(ms *sqlite.MessageStore) {
				for i := 0; i < 5; i++ {
					err := ms.Append(ctx, "ws-order", &store.Message{
						ID:        fmt.Sprintf("msg-%d", i),
						SessionID: "sess-1",
						Role:      store.MessageRoleUser,
						Content:   fmt.Sprintf("Message %d", i),
						CreatedAt: base.Add(time.Duration(i) * time.Hour),
					})
					require.NoError(t, err)
				}
			},
			workspace: "ws-order",
			n:         3,
			wantLen:   3,
			wantFirst: "msg-0",
			wantLast:  "msg-2",
		},
		{
			name: "n_greater_than_total_returns_all",
			setup: func(ms *sqlite.MessageStore) {
				for i := 0; i < 3; i++ {
					err := ms.Append(ctx, "ws-overflow", &store.Message{
						ID:        fmt.Sprintf("overflow-msg-%d", i),
						SessionID: "sess-1",
						Role:      store.MessageRoleUser,
						Content:   fmt.Sprintf("Message %d", i),
						CreatedAt: base.Add(time.Duration(i) * time.Hour),
					})
					require.NoError(t, err)
				}
			},
			workspace: "ws-overflow",
			n:         100,
			wantLen:   3,
			wantFirst: "overflow-msg-0",
			wantLast:  "overflow-msg-2",
		},
		{
			name:      "empty_workspace_returns_empty_slice",
			setup:     func(_ *sqlite.MessageStore) {},
			workspace: "ws-empty",
			n:         10,
			wantLen:   0,
		},
		{
			name: "workspace_isolation",
			setup: func(ms *sqlite.MessageStore) {
				for i := 0; i < 3; i++ {
					err := ms.Append(ctx, "ws-iso-1", &store.Message{
						ID:        fmt.Sprintf("ws1-msg-%d", i),
						SessionID: "sess-1",
						Role:      store.MessageRoleUser,
						Content:   fmt.Sprintf("WS1 Message %d", i),
						CreatedAt: base.Add(time.Duration(i) * time.Hour),
					})
					require.NoError(t, err)
				}
				err := ms.Append(ctx, "ws-iso-2", &store.Message{
					ID:        "ws2-msg-0",
					SessionID: "sess-2",
					Role:      store.MessageRoleUser,
					Content:   "WS2 Message 0",
					CreatedAt: base,
				})
				require.NoError(t, err)
			},
			workspace: "ws-iso-1",
			n:         10,
			wantLen:   3,
			wantFirst: "ws1-msg-0",
			wantLast:  "ws1-msg-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testDBPath(t, "messages-getoldest-"+tt.name)
			ms, err := sqlite.NewMessageStore(db)
			require.NoError(t, err)
			defer func() { _ = ms.Close() }()

			tt.setup(ms)

			got, err := ms.GetOldest(ctx, tt.workspace, tt.n)
			require.NoError(t, err)
			assert.Len(t, got, tt.wantLen)

			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, got[0].ID, "first message should be oldest")
				assert.Equal(t, tt.wantLast, got[tt.wantLen-1].ID, "last message should be newest of the returned set")
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	summaries := []*store.Summary{
		{ID: "sum-1", WorkspaceID: "ws-1", FromTime: base, ToTime: base.Add(1 * time.Hour), Content: "Discussion about K8s", CreatedAt: base.Add(1 * time.Hour), Status: store.SummaryStatusCommitted},
		{ID: "sum-2", WorkspaceID: "ws-1", FromTime: base.Add(1 * time.Hour), ToTime: base.Add(2 * time.Hour), Content: "Terraform planning", CreatedAt: base.Add(2 * time.Hour), Status: store.SummaryStatusCommitted},
		{ID: "sum-3", WorkspaceID: "ws-1", FromTime: base.Add(2 * time.Hour), ToTime: base.Add(3 * time.Hour), Content: "Monitoring setup", CreatedAt: base.Add(3 * time.Hour), Status: store.SummaryStatusCommitted},
	}

	for _, s := range summaries {
		err = ss.Store(ctx, "ws-1", s)
		require.NoError(t, err)
	}

	// GetByRange
	results, err := ss.GetByRange(ctx, "ws-1", base, base.Add(2*time.Hour))
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// GetLatest
	results, err = ss.GetLatest(ctx, "ws-1", 2)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "Monitoring setup", results[0].Content)
}

func TestSummaryStore_StoreWithMessageIDs(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-msgids")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	summary := &store.Summary{
		ID:          "sum-1",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Summary with message refs",
		MessageIDs:  []string{"msg-1", "msg-2", "msg-3"},
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	}

	err = ss.Store(ctx, "ws-1", summary)
	require.NoError(t, err)

	results, err := ss.GetLatest(ctx, "ws-1", 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, []string{"msg-1", "msg-2", "msg-3"}, results[0].MessageIDs)
}

func TestSummaryStore_Store_EmptyStatus_ReturnsError(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-empty-status-error")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Store a summary with Status="" (zero value) — must return an error.
	summary := &store.Summary{
		ID:          "sum-no-status",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Status not set",
		CreatedAt:   base.Add(1 * time.Hour),
		// Status intentionally left as zero value ""
	}
	err = ss.Store(ctx, "ws-1", summary)
	require.Error(t, err, "Store with empty Status should return an error")
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeAgentLoopInvalidInput), "expected CodeAgentLoopInvalidInput, got: %v", err)
}

func TestSummaryStore_GetByRangeEmpty(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-empty")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	results, err := ss.GetByRange(ctx, "ws-1", base, base.Add(1*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSummaryStore_WorkspaceIsolation(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-isolation")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	err = ss.Store(ctx, "ws-1", &store.Summary{
		ID: "sum-1", WorkspaceID: "ws-1", FromTime: base, ToTime: base.Add(1 * time.Hour),
		Content: "WS1 summary", CreatedAt: base.Add(1 * time.Hour), Status: store.SummaryStatusCommitted,
	})
	require.NoError(t, err)

	err = ss.Store(ctx, "ws-2", &store.Summary{
		ID: "sum-2", WorkspaceID: "ws-2", FromTime: base, ToTime: base.Add(1 * time.Hour),
		Content: "WS2 summary", CreatedAt: base.Add(1 * time.Hour), Status: store.SummaryStatusCommitted,
	})
	require.NoError(t, err)

	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "WS1 summary", results[0].Content)
}

func TestSummaryStore_Confirm_PromotesPendingToCommitted(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-confirm-promote")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Pending compaction",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusPending,
	}
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	// Before Confirm: should not appear in queries
	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Empty(t, results, "pending summary should not be visible before Confirm")

	// Call Confirm
	err = ss.Confirm(ctx, "ws-1", "sum-pending")
	require.NoError(t, err)

	// After Confirm: should appear as committed
	results, err = ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sum-pending", results[0].ID)
	assert.Equal(t, store.SummaryStatusCommitted, results[0].Status)
}

func TestSummaryStore_Confirm_NotFound_ReturnsError(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-confirm-notfound")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	err = ss.Confirm(ctx, "ws-1", "nonexistent-id")
	assert.Error(t, err, "Confirm with non-existent summaryID should return error")
}

func TestSummaryStore_Confirm_WrongWorkspace_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-confirm-wrongws")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Pending compaction",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusPending,
	}
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	// Confirm using a different workspace — should return not-found error.
	err = ss.Confirm(ctx, "ws-2", "sum-pending")
	require.Error(t, err, "Confirm with wrong workspace should return error")
	assert.True(t, sigilerr.IsNotFound(err), "expected CodeStoreEntityNotFound, got: %v", err)

	// Summary in ws-1 should still be pending (not visible to committed queries).
	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Empty(t, results, "summary in ws-1 should still be pending after failed Confirm")
}

func TestSummaryStore_Confirm_AlreadyCommitted_ReturnsConflict(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-confirm-already-committed")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Pending compaction",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusPending,
	}
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	// First Confirm — succeeds, status becomes committed.
	err = ss.Confirm(ctx, "ws-1", "sum-pending")
	require.NoError(t, err, "first Confirm should succeed")

	// Second Confirm — must return conflict because status is 'committed', not 'pending'.
	// Documents that Confirm is NOT idempotent: double-confirm returns a conflict error.
	err = ss.Confirm(ctx, "ws-1", "sum-pending")
	require.Error(t, err, "second Confirm on already-committed summary should return error")
	assert.True(t, sigilerr.IsConflict(err), "expected CodeStoreConflict on double-confirm, got: %v", err)
	assert.Contains(t, err.Error(), "expected status pending, got committed")
}

func TestSummaryStore_GetByRange_ExcludesPendingSummaries(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-getbyrange-pending")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	committed := &store.Summary{
		ID:          "sum-committed",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Committed summary",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	}
	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base.Add(1 * time.Hour),
		ToTime:      base.Add(2 * time.Hour),
		Content:     "Pending summary",
		CreatedAt:   base.Add(2 * time.Hour),
		Status:      store.SummaryStatusPending,
	}

	err = ss.Store(ctx, "ws-1", committed)
	require.NoError(t, err)
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	results, err := ss.GetByRange(ctx, "ws-1", base, base.Add(2*time.Hour))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sum-committed", results[0].ID)
}

func TestSummaryStore_GetLatest_ExcludesPendingSummaries(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-getlatest-pending")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	committed := &store.Summary{
		ID:          "sum-committed",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Committed summary",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	}
	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base.Add(1 * time.Hour),
		ToTime:      base.Add(2 * time.Hour),
		Content:     "Pending summary",
		CreatedAt:   base.Add(2 * time.Hour),
		Status:      store.SummaryStatusPending,
	}

	err = ss.Store(ctx, "ws-1", committed)
	require.NoError(t, err)
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sum-committed", results[0].ID)
}

func TestSummaryStore_Delete_RemovesSummary(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-delete-removes")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	summary := &store.Summary{
		ID:          "sum-1",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "To be deleted",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	}
	err = ss.Store(ctx, "ws-1", summary)
	require.NoError(t, err)

	// Verify it exists before deletion.
	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)

	err = ss.Delete(ctx, "ws-1", "sum-1")
	require.NoError(t, err)

	// GetLatest should no longer return the deleted summary.
	results, err = ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Empty(t, results)

	// GetByRange should also not return it.
	results, err = ss.GetByRange(ctx, "ws-1", base, base.Add(1*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSummaryStore_Delete_WorkspaceScoping(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-delete-scoping")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	err = ss.Store(ctx, "ws-1", &store.Summary{
		ID:          "sum-ws1",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "WS1 summary",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	})
	require.NoError(t, err)

	err = ss.Store(ctx, "ws-2", &store.Summary{
		ID:          "sum-ws2",
		WorkspaceID: "ws-2",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "WS2 summary",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusCommitted,
	})
	require.NoError(t, err)

	// Delete from ws-1 only.
	err = ss.Delete(ctx, "ws-1", "sum-ws1")
	require.NoError(t, err)

	// ws-1 should be empty.
	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Empty(t, results)

	// ws-2 should be unaffected.
	results, err = ss.GetLatest(ctx, "ws-2", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "WS2 summary", results[0].Content)
}

func TestSummaryStore_Delete_NonExistentID(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-delete-nonexistent")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	// Deleting a non-existent summary should not return an error.
	err = ss.Delete(ctx, "ws-1", "does-not-exist")
	assert.NoError(t, err)
}

func TestSummaryStore_Delete_PendingSummary(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries-delete-pending")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer func() { _ = ss.Close() }()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base,
		ToTime:      base.Add(1 * time.Hour),
		Content:     "Orphaned pending compaction",
		CreatedAt:   base.Add(1 * time.Hour),
		Status:      store.SummaryStatusPending,
	}
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err)

	err = ss.Delete(ctx, "ws-1", "sum-pending")
	require.NoError(t, err)

	// Pending summaries are excluded from queries; confirm deletion does not
	// cause errors and the record is truly gone (Confirm should now fail).
	err = ss.Confirm(ctx, "ws-1", "sum-pending")
	assert.Error(t, err, "Confirm should fail after Delete removes the pending summary")
}

// TestSummaryStore_Migration_AddsStatusColumn verifies that migrateSummaries adds the
// status column to a pre-existing summaries table that was created without it,
// and that existing rows receive the default 'committed' value.
func TestSummaryStore_Migration_AddsStatusColumn(t *testing.T) {
	ctx := context.Background()
	dbPath := testDBPath(t, "summaries-migrate-status")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Bootstrap a database with the old schema — summaries table without the status column.
	{
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
		require.NoError(t, err)

		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS summaries (
	id           TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL,
	from_time    TEXT NOT NULL,
	to_time      TEXT NOT NULL,
	content      TEXT NOT NULL DEFAULT '',
	message_ids  TEXT NOT NULL DEFAULT '[]',
	created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_summaries_workspace ON summaries(workspace_id);
`)
		require.NoError(t, err, "setting up old schema without status column")

		// Verify status column is absent in the baseline schema.
		rows, err := db.Query("PRAGMA table_info(summaries)")
		require.NoError(t, err)
		found := false
		for rows.Next() {
			var cid int
			var name, colType string
			var notNull int
			var dfltValue sql.NullString
			var pk int
			require.NoError(t, rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk))
			if name == "status" {
				found = true
			}
		}
		require.NoError(t, rows.Err())
		_ = rows.Close()
		require.False(t, found, "status column should not exist in the old schema")

		// Insert a row using the old schema (no status column).
		_, err = db.Exec(`INSERT INTO summaries (id, workspace_id, from_time, to_time, content, message_ids, created_at)
VALUES ('pre-migration-sum', 'ws-1', ?, ?, 'Pre-migration content', '[]', ?)`,
			base.Format(time.RFC3339), base.Add(1*time.Hour).Format(time.RFC3339), base.Add(1*time.Hour).Format(time.RFC3339),
		)
		require.NoError(t, err, "inserting row into old-schema table")

		_ = db.Close()
	}

	// Open via NewSummaryStore — this runs migrateSummaries which must add the status column.
	ss, err := sqlite.NewSummaryStore(dbPath)
	require.NoError(t, err, "NewSummaryStore should succeed and run migration")
	defer func() { _ = ss.Close() }()

	// Verify the pre-migration row received the DEFAULT 'committed' value.
	results, err := ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	require.Len(t, results, 1, "pre-migration row should be visible as committed")
	assert.Equal(t, "pre-migration-sum", results[0].ID)
	assert.Equal(t, store.SummaryStatusCommitted, results[0].Status, "existing row should default to committed after migration")

	// Verify new pending summaries can be stored and confirmed.
	pending := &store.Summary{
		ID:          "post-migration-pending",
		WorkspaceID: "ws-1",
		FromTime:    base.Add(1 * time.Hour),
		ToTime:      base.Add(2 * time.Hour),
		Content:     "Post-migration pending",
		CreatedAt:   base.Add(2 * time.Hour),
		Status:      store.SummaryStatusPending,
	}
	err = ss.Store(ctx, "ws-1", pending)
	require.NoError(t, err, "should be able to store pending summary after migration")

	// Pending summary should not appear in queries before Confirm.
	results, err = ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	require.Len(t, results, 1, "only committed summaries should be visible before Confirm")

	err = ss.Confirm(ctx, "ws-1", "post-migration-pending")
	require.NoError(t, err, "Confirm should succeed after migration")

	// After Confirm both summaries should be visible.
	results, err = ss.GetLatest(ctx, "ws-1", 10)
	require.NoError(t, err)
	assert.Len(t, results, 2, "both summaries should be visible after Confirm")
}

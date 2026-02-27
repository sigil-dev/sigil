// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
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
		{ID: "sum-1", WorkspaceID: "ws-1", FromTime: base, ToTime: base.Add(1 * time.Hour), Content: "Discussion about K8s", CreatedAt: base.Add(1 * time.Hour)},
		{ID: "sum-2", WorkspaceID: "ws-1", FromTime: base.Add(1 * time.Hour), ToTime: base.Add(2 * time.Hour), Content: "Terraform planning", CreatedAt: base.Add(2 * time.Hour)},
		{ID: "sum-3", WorkspaceID: "ws-1", FromTime: base.Add(2 * time.Hour), ToTime: base.Add(3 * time.Hour), Content: "Monitoring setup", CreatedAt: base.Add(3 * time.Hour)},
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
	}

	err = ss.Store(ctx, "ws-1", summary)
	require.NoError(t, err)

	results, err := ss.GetLatest(ctx, "ws-1", 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, []string{"msg-1", "msg-2", "msg-3"}, results[0].MessageIDs)
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
		Content: "WS1 summary", CreatedAt: base.Add(1 * time.Hour),
	})
	require.NoError(t, err)

	err = ss.Store(ctx, "ws-2", &store.Summary{
		ID: "sum-2", WorkspaceID: "ws-2", FromTime: base, ToTime: base.Add(1 * time.Hour),
		Content: "WS2 summary", CreatedAt: base.Add(1 * time.Hour),
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
		Status:      "pending",
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
	assert.Equal(t, "committed", results[0].Status)
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
	}
	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base.Add(1 * time.Hour),
		ToTime:      base.Add(2 * time.Hour),
		Content:     "Pending summary",
		CreatedAt:   base.Add(2 * time.Hour),
		Status:      "pending",
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
	}
	pending := &store.Summary{
		ID:          "sum-pending",
		WorkspaceID: "ws-1",
		FromTime:    base.Add(1 * time.Hour),
		ToTime:      base.Add(2 * time.Hour),
		Content:     "Pending summary",
		CreatedAt:   base.Add(2 * time.Hour),
		Status:      "pending",
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

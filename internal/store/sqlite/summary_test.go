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

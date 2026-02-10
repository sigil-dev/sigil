// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorStore_StoreAndSearch(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors")
	vs, err := sqlite.NewVectorStore(db, 3) // 3-dimensional embeddings for testing
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	// Store vectors
	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, map[string]any{"source": "test1"})
	require.NoError(t, err)

	err = vs.Store(ctx, "v2", []float32{0.0, 1.0, 0.0}, map[string]any{"source": "test2"})
	require.NoError(t, err)

	err = vs.Store(ctx, "v3", []float32{0.9, 0.1, 0.0}, map[string]any{"source": "test3"})
	require.NoError(t, err)

	// Search for nearest to [1, 0, 0]
	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 2, nil)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "v1", results[0].ID) // exact match should be first
}

func TestVectorStore_Delete(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-delete")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, nil)
	require.NoError(t, err)

	err = vs.Delete(ctx, []string{"v1"})
	require.NoError(t, err)

	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 10, nil)
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestVectorStore_StoreUpsert(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-upsert")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	// Store initial vector
	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, map[string]any{"version": float64(1)})
	require.NoError(t, err)

	// Upsert with new embedding and metadata
	err = vs.Store(ctx, "v1", []float32{0.0, 1.0, 0.0}, map[string]any{"version": float64(2)})
	require.NoError(t, err)

	// Search should find the updated vector near [0,1,0]
	results, err := vs.Search(ctx, []float32{0.0, 1.0, 0.0}, 1, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "v1", results[0].ID)
	assert.Equal(t, float64(2), results[0].Metadata["version"])
}

func TestVectorStore_SearchWithMetadata(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-meta")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, map[string]any{"tag": "a"})
	require.NoError(t, err)

	err = vs.Store(ctx, "v2", []float32{0.9, 0.1, 0.0}, map[string]any{"tag": "b"})
	require.NoError(t, err)

	// Search returns metadata
	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 2, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "a", results[0].Metadata["tag"])
}

func TestVectorStore_DeleteMultiple(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-del-multi")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	for _, id := range []string{"v1", "v2", "v3"} {
		err = vs.Store(ctx, id, []float32{1.0, 0.0, 0.0}, nil)
		require.NoError(t, err)
	}

	err = vs.Delete(ctx, []string{"v1", "v3"})
	require.NoError(t, err)

	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 10, nil)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "v2", results[0].ID)
}

func TestVectorStore_DeleteEmpty(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-del-empty")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	// Deleting nothing should not error
	err = vs.Delete(ctx, nil)
	require.NoError(t, err)

	err = vs.Delete(ctx, []string{})
	require.NoError(t, err)
}

func TestVectorStore_SearchEmpty(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-search-empty")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer func() { _ = vs.Close() }()

	// Search on empty store returns empty results
	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 5, nil)
	require.NoError(t, err)
	assert.Empty(t, results)
}

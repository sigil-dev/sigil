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

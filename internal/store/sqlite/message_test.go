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

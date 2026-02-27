// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompaction_ShouldTrigger(t *testing.T) {
	tests := []struct {
		name      string
		count     int64
		batchSize int
		want      bool
	}{
		{"below threshold", 30, 50, false},
		{"at threshold", 50, 50, true},
		{"above threshold", 75, 50, true},
		{"zero", 0, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agent.ShouldCompact(tt.count, tt.batchSize)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewCompactor_Validation(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()

	tests := []struct {
		name    string
		cfg     agent.CompactorConfig
		wantErr string
	}{
		{
			name:    "nil MemoryStore",
			cfg:     agent.CompactorConfig{VectorStore: vs, BatchSize: 5},
			wantErr: "MemoryStore must not be nil",
		},
		{
			name:    "nil VectorStore",
			cfg:     agent.CompactorConfig{MemoryStore: ms, BatchSize: 5},
			wantErr: "VectorStore must not be nil",
		},
		{
			name:    "zero BatchSize",
			cfg:     agent.CompactorConfig{MemoryStore: ms, VectorStore: vs, BatchSize: 0},
			wantErr: "BatchSize must be positive",
		},
		{
			name:    "negative BatchSize",
			cfg:     agent.CompactorConfig{MemoryStore: ms, VectorStore: vs, BatchSize: -1},
			wantErr: "BatchSize must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := agent.NewCompactor(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCompaction_RollMessage(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	ss := newMockSessionStore()

	c, err := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  ms,
		VectorStore:  vs,
		SessionStore: ss,
		BatchSize:    50,
	})
	require.NoError(t, err)

	ctx := context.Background()
	msg := &store.Message{
		ID:      "msg-roll-1",
		Role:    store.MessageRoleUser,
		Content: "Hello, world",
	}

	err = c.RollMessage(ctx, "ws-1", "sess-1", msg)
	require.NoError(t, err)

	count, err := ms.Messages().Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestCompaction_RollMessage_MemoryStoreFailure(t *testing.T) {
	expectedErr := fmt.Errorf("memory store append failed")
	msgStoreErr := &mockMessageStoreError{appendErr: expectedErr}
	memStoreErr := &mockMemoryStoreWithError{
		messages:  msgStoreErr,
		summaries: &mockSummaryStore{},
		knowledge: &mockKnowledgeStore{},
	}
	vs := newMockVectorStore()
	ss := newMockSessionStore()

	c, err := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  memStoreErr,
		VectorStore:  vs,
		SessionStore: ss,
		BatchSize:    50,
	})
	require.NoError(t, err)

	ctx := context.Background()
	msg := &store.Message{
		ID:      "msg-err-1",
		Role:    store.MessageRoleUser,
		Content: "Test message",
	}

	err = c.RollMessage(ctx, "ws-1", "sess-1", msg)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)

	// Verify VectorStore.Store was NOT called
	assert.Empty(t, vs.vectors, "VectorStore should not have been called after message append error")
}

func TestCompaction_RollMessage_VectorStoreFailure(t *testing.T) {
	ms := newMockMemoryStore()
	expectedErr := fmt.Errorf("vector store write failed")
	vs := &mockVectorStoreError{
		mockVectorStore: mockVectorStore{vectors: make(map[string]mockVector)},
		storeErr:        expectedErr,
	}
	ss := newMockSessionStore()

	c, err := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  ms,
		VectorStore:  vs,
		SessionStore: ss,
		BatchSize:    50,
	})
	require.NoError(t, err)

	ctx := context.Background()
	msg := &store.Message{
		ID:      "msg-vec-err-1",
		Role:    store.MessageRoleUser,
		Content: "Test message",
	}

	err = c.RollMessage(ctx, "ws-1", "sess-1", msg)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)

	// Verify message WAS appended to memory store (before vector store error)
	count, err := ms.Messages().Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

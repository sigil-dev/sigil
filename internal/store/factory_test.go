// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	_ "github.com/sigil-dev/sigil/internal/store/sqlite" // register sqlite backend
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWorkspaceStores_SQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "sqlite",
	}

	ss, ms, vs, err := store.NewWorkspaceStores(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, ss)
	assert.NotNil(t, ms)
	assert.NotNil(t, vs)
}

func TestNewGatewayStore_SQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "sqlite",
	}

	gs, err := store.NewGatewayStore(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, gs)
}

func TestNewWorkspaceStores_UnknownBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "unknown",
	}

	_, _, _, err := store.NewWorkspaceStores(cfg, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestNewGatewayStore_UnknownBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "unknown",
	}

	_, err := store.NewGatewayStore(cfg, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestNewWorkspaceStores_MemoryStoreSubStores(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "sqlite",
	}

	_, ms, _, err := store.NewWorkspaceStores(cfg, dir)
	require.NoError(t, err)

	assert.NotNil(t, ms.Messages())
	assert.NotNil(t, ms.Summaries())
	assert.NotNil(t, ms.Knowledge())

	require.NoError(t, ms.Close())
}

func TestNewWorkspaceStores_DefaultBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{} // empty backend defaults to sqlite

	ss, ms, vs, err := store.NewWorkspaceStores(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, ss)
	assert.NotNil(t, ms)
	assert.NotNil(t, vs)
}

func TestNewGatewayStore_DefaultBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{} // empty backend defaults to sqlite

	gs, err := store.NewGatewayStore(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, gs)
}

// TestRegisterBackend_Concurrent verifies that RegisterBackend is goroutine-safe
// and can handle concurrent registrations without race conditions.
func TestRegisterBackend_Concurrent(t *testing.T) {
	const numGoroutines = 10
	const registrationsPerGoroutine = 10

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()
			for j := 0; j < registrationsPerGoroutine; j++ {
				name := fmt.Sprintf("backend-%d-%d", goroutineID, j)
				store.RegisterBackend(name,
					func(_ string, _ int) (store.SessionStore, store.MemoryStore, store.VectorStore, error) {
						return nil, nil, nil, nil
					},
					func(_ string) (store.GatewayStore, error) {
						return nil, nil
					},
				)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// mockClosableStore implements a store with a configurable Close error.
type mockClosableStore struct {
	closeErr error
}

func (m *mockClosableStore) Close() error {
	return m.closeErr
}

// mockMessageStore implements MessageStore with configurable Close error.
type mockMessageStore struct {
	mockClosableStore
}

func (m *mockMessageStore) Append(ctx context.Context, workspaceID string, msg *store.Message) error {
	return nil
}

func (m *mockMessageStore) Search(ctx context.Context, workspaceID string, query string, opts store.SearchOpts) ([]*store.Message, error) {
	return nil, nil
}

func (m *mockMessageStore) GetRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*store.Message, error) {
	return nil, nil
}

func (m *mockMessageStore) Count(ctx context.Context, workspaceID string) (int64, error) {
	return 0, nil
}

func (m *mockMessageStore) Trim(ctx context.Context, workspaceID string, keepLast int) (int64, error) {
	return 0, nil
}

// mockSummaryStore implements SummaryStore with configurable Close error.
type mockSummaryStore struct {
	mockClosableStore
}

func (m *mockSummaryStore) Store(ctx context.Context, workspaceID string, summary *store.Summary) error {
	return nil
}

func (m *mockSummaryStore) GetByRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*store.Summary, error) {
	return nil, nil
}

func (m *mockSummaryStore) GetLatest(ctx context.Context, workspaceID string, n int) ([]*store.Summary, error) {
	return nil, nil
}

// mockKnowledgeStore implements KnowledgeStore with configurable Close error.
type mockKnowledgeStore struct {
	mockClosableStore
}

func (m *mockKnowledgeStore) PutEntity(ctx context.Context, workspaceID string, entity *store.Entity) error {
	return nil
}

func (m *mockKnowledgeStore) GetEntity(ctx context.Context, workspaceID string, id string) (*store.Entity, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) FindEntities(ctx context.Context, workspaceID string, query store.EntityQuery) ([]*store.Entity, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) PutRelationship(ctx context.Context, rel *store.Relationship) error {
	return nil
}

func (m *mockKnowledgeStore) GetRelationships(ctx context.Context, entityID string, opts store.RelOpts) ([]*store.Relationship, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) PutFact(ctx context.Context, workspaceID string, fact *store.Fact) error {
	return nil
}

func (m *mockKnowledgeStore) FindFacts(ctx context.Context, workspaceID string, query store.FactQuery) ([]*store.Fact, error) {
	return nil, nil
}

func (m *mockKnowledgeStore) Traverse(ctx context.Context, startID string, depth int, filter store.TraversalFilter) (*store.Graph, error) {
	return nil, nil
}

func TestCompositeMemoryStore_Close(t *testing.T) {
	tests := []struct {
		name          string
		messagesErr   error
		summariesErr  error
		knowledgeErr  error
		wantNil       bool
		wantContains  []string // error messages that should be present
	}{
		{
			name:         "all stores close successfully",
			messagesErr:  nil,
			summariesErr: nil,
			knowledgeErr: nil,
			wantNil:      true,
		},
		{
			name:         "messages store fails",
			messagesErr:  fmt.Errorf("messages close error"),
			summariesErr: nil,
			knowledgeErr: nil,
			wantNil:      false,
			wantContains: []string{"messages close error"},
		},
		{
			name:         "summaries store fails",
			messagesErr:  nil,
			summariesErr: fmt.Errorf("summaries close error"),
			knowledgeErr: nil,
			wantNil:      false,
			wantContains: []string{"summaries close error"},
		},
		{
			name:         "knowledge store fails",
			messagesErr:  nil,
			summariesErr: nil,
			knowledgeErr: fmt.Errorf("knowledge close error"),
			wantNil:      false,
			wantContains: []string{"knowledge close error"},
		},
		{
			name:         "all stores fail - all errors preserved",
			messagesErr:  fmt.Errorf("messages close error"),
			summariesErr: fmt.Errorf("summaries close error"),
			knowledgeErr: fmt.Errorf("knowledge close error"),
			wantNil:      false,
			wantContains: []string{
				"messages close error",
				"summaries close error",
				"knowledge close error",
			},
		},
		{
			name:         "two stores fail - both errors preserved",
			messagesErr:  fmt.Errorf("messages close error"),
			summariesErr: nil,
			knowledgeErr: fmt.Errorf("knowledge close error"),
			wantNil:      false,
			wantContains: []string{
				"messages close error",
				"knowledge close error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := &mockMessageStore{mockClosableStore{closeErr: tt.messagesErr}}
			sums := &mockSummaryStore{mockClosableStore{closeErr: tt.summariesErr}}
			know := &mockKnowledgeStore{mockClosableStore{closeErr: tt.knowledgeErr}}

			ms := store.NewCompositeMemoryStore(msgs, sums, know)
			err := ms.Close()

			if tt.wantNil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				errStr := err.Error()
				for _, want := range tt.wantContains {
					assert.Contains(t, errStr, want, "expected error to contain %q", want)
				}
			}
		})
	}
}

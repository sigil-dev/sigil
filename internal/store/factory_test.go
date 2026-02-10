// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"fmt"
	"testing"

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

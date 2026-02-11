// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWorkspaceStores_PartialFailureCleanup(t *testing.T) {
	tests := []struct {
		name              string
		setupFailure      func(dir string) // Function to cause a partial failure
		expectErrContains string
	}{
		{
			name: "memory db creation fails after session store created",
			setupFailure: func(dir string) {
				// Make memory.db path a directory to trigger failure
				memPath := filepath.Join(dir, "memory.db")
				err := os.Mkdir(memPath, 0o755)
				require.NoError(t, err)
			},
			expectErrContains: "creating message store",
		},
		{
			name: "knowledge store creation fails",
			setupFailure: func(dir string) {
				// Make knowledge.db path a directory to trigger failure
				knowledgePath := filepath.Join(dir, "knowledge.db")
				err := os.Mkdir(knowledgePath, 0o755)
				require.NoError(t, err)
			},
			expectErrContains: "creating knowledge store",
		},
		{
			name: "vector store creation fails",
			setupFailure: func(dir string) {
				// Make vectors.db path a directory to trigger failure
				vectorPath := filepath.Join(dir, "vectors.db")
				err := os.Mkdir(vectorPath, 0o755)
				require.NoError(t, err)
			},
			expectErrContains: "creating vector store",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testDir(t)

			// Setup the failure condition
			tt.setupFailure(dir)

			// Try to create workspace stores - should fail and cleanup
			cfg := &store.StorageConfig{Backend: "sqlite"}
			ss, ms, vs, err := store.NewWorkspaceStores(cfg, dir)

			// Should return error
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErrContains)

			// Should not return any stores
			assert.Nil(t, ss)
			assert.Nil(t, ms)
			assert.Nil(t, vs)

			// Note: We can't easily test that cleanup errors are aggregated
			// without more invasive mocking, but the implementation should
			// use errors.Join to aggregate cleanup errors with the primary error.
		})
	}
}

func TestNewWorkspaceStores_Success(t *testing.T) {
	dir := testDir(t)

	cfg := &store.StorageConfig{Backend: "sqlite"}
	ss, ms, vs, err := store.NewWorkspaceStores(cfg, dir)
	require.NoError(t, err)
	require.NotNil(t, ss)
	require.NotNil(t, ms)
	require.NotNil(t, vs)

	// Cleanup
	require.NoError(t, ms.Close())
	require.NoError(t, vs.Close())
}

func TestNewGatewayStore_Success(t *testing.T) {
	dir := testDir(t)

	cfg := &store.StorageConfig{Backend: "sqlite"}
	gs, err := store.NewGatewayStore(cfg, dir)
	require.NoError(t, err)
	require.NotNil(t, gs)

	// Cleanup
	require.NoError(t, gs.Close())
}

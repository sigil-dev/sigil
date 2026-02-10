// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// testDir creates a temp directory for a test and returns cleanup func.
func testDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sigil-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// testDBPath returns a temp SQLite database path.
func testDBPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(testDir(t), name+".db")
}

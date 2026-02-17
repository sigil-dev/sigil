// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPortConstants_RustAndTypeScriptMatch verifies that the gateway port
// constant in the Tauri Rust code matches the default in the TypeScript API
// client. These files use "MUST match" comments but this test catches drift.
func TestPortConstants_RustAndTypeScriptMatch(t *testing.T) {
	// Find project root relative to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	rustPath := filepath.Join(projectRoot, "ui", "src-tauri", "src", "main.rs")
	tsPath := filepath.Join(projectRoot, "ui", "src", "lib", "api", "client.ts")

	rustSrc, err := os.ReadFile(rustPath)
	require.NoError(t, err, "failed to read Rust source: %s", rustPath)

	tsSrc, err := os.ReadFile(tsPath)
	require.NoError(t, err, "failed to read TypeScript source: %s", tsPath)

	rustPortRe := regexp.MustCompile(`DEFAULT_GATEWAY_PORT:\s*u16\s*=\s*(\d+)`)
	tsPortRe := regexp.MustCompile(`localhost:(\d+)`)

	rustMatch := rustPortRe.FindSubmatch(rustSrc)
	require.NotNil(t, rustMatch, "could not find DEFAULT_GATEWAY_PORT in main.rs")

	tsMatch := tsPortRe.FindSubmatch(tsSrc)
	require.NotNil(t, tsMatch, "could not find localhost port in client.ts")

	assert.Equal(t, string(rustMatch[1]), string(tsMatch[1]),
		"Rust DEFAULT_GATEWAY_PORT (%s) and TypeScript API_BASE port (%s) must match",
		string(rustMatch[1]), string(tsMatch[1]))
}

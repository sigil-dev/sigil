// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package wasm_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/plugin/wasm"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", name)
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(testdataPath(name))
	require.NoError(t, err, "loading fixture %s", name)
	return data
}

func TestWasmHost_LoadAndCallModule(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	ctx := context.Background()
	mod, err := host.LoadModule(ctx, "add-mod", loadFixture(t, "add.wasm"))
	require.NoError(t, err)
	defer func() { require.NoError(t, mod.Close(ctx)) }()

	results, err := mod.CallWithTimeout(ctx, "add", 2, 3)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uint64(5), results[0])
}

func TestWasmHost_ModuleIsolation(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	ctx := context.Background()
	addWasm := loadFixture(t, "add.wasm")

	mod1, err := host.LoadModule(ctx, "mod-alpha", addWasm)
	require.NoError(t, err)

	mod2, err := host.LoadModule(ctx, "mod-beta", addWasm)
	require.NoError(t, err)

	// Verify independent names.
	assert.Equal(t, "mod-alpha", mod1.Name())
	assert.Equal(t, "mod-beta", mod2.Name())

	// Close first module; second must still work.
	require.NoError(t, mod1.Close(ctx))

	results, err := mod2.CallWithTimeout(ctx, "add", 10, 20)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uint64(30), results[0])
}

func TestWasmHost_ExecTimeoutEnforced(t *testing.T) {
	timeout := 100 * time.Millisecond
	host, err := wasm.NewHost(wasm.WithExecTimeout(timeout))
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	assert.Equal(t, timeout, host.ExecTimeout())

	ctx := context.Background()
	mod, err := host.LoadModule(ctx, "looper", loadFixture(t, "infinite_loop.wasm"))
	require.NoError(t, err)
	defer func() { _ = mod.Close(ctx) }()

	_, err = mod.CallWithTimeout(ctx, "loop")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestWasmHost_LoadModule_EmptyName(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	ctx := context.Background()
	wasmBytes := loadFixture(t, "add.wasm")

	tests := []struct {
		name      string
		modName   string
		wantError string
	}{
		{"empty string", "", "module name must not be empty"},
		{"whitespace only", "   ", "module name must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := host.LoadModule(ctx, tt.modName, wasmBytes)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestWasmModule_CallWithTimeout_MissingFunction(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	ctx := context.Background()
	mod, err := host.LoadModule(ctx, "test-mod", loadFixture(t, "add.wasm"))
	require.NoError(t, err)
	defer func() { require.NoError(t, mod.Close(ctx)) }()

	_, err = mod.CallWithTimeout(ctx, "nonexistent_function")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_function")
	assert.Contains(t, err.Error(), "not exported")

	// Verify it uses the call failure code, not start failure code
	code := sigilerr.CodeOf(err)
	assert.Equal(t, sigilerr.CodePluginRuntimeCallFailure, code, "should use call failure code for missing function")
	assert.NotEqual(t, sigilerr.CodePluginRuntimeStartFailure, code, "should not use start failure code for call-time error")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package wasm_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin/wasm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWasmHost_Create(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()
	assert.NotNil(t, host)
}

func TestWasmHost_LoadModule(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer func() { require.NoError(t, host.Close()) }()

	ctx := context.Background()

	_, err = host.LoadModule(ctx, "test-module", minimalWasm())
	require.NoError(t, err)
}

func minimalWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
	}
}

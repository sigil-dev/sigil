// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSpec(t *testing.T) {
	spec, err := generateSpec()
	require.NoError(t, err)
	assert.Contains(t, string(spec), "openapi")
	assert.Contains(t, string(spec), "3.1")
	assert.Contains(t, string(spec), "/api/v1/workspaces")
	assert.Contains(t, string(spec), "/api/v1/chat")
	assert.Contains(t, string(spec), "/api/v1/plugins")
	assert.Contains(t, string(spec), "/health")
}

func TestGenerateSpec_ValidJSON(t *testing.T) {
	spec, err := generateSpec()
	require.NoError(t, err)
	// Spec should be valid JSON (not empty, starts with {)
	assert.True(t, len(spec) > 100, "spec should be non-trivial")
	assert.Equal(t, byte('{'), spec[0], "spec should be JSON object")
}

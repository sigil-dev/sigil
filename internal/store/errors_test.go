// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
)

// TestSentinelErrors_Direct verifies the sentinel errors can be checked directly.
func TestSentinelErrors_Direct(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"ErrNotFound direct", store.ErrNotFound, store.ErrNotFound},
		{"ErrConflict direct", store.ErrConflict, store.ErrConflict},
		{"ErrInvalidInput direct", store.ErrInvalidInput, store.ErrInvalidInput},
		{"ErrDatabase direct", store.ErrDatabase, store.ErrDatabase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.err, tt.sentinel)
		})
	}
}

// TestSentinelErrors_Wrapped verifies sentinel errors work when wrapped with fmt.Errorf.
func TestSentinelErrors_Wrapped(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{
			name:     "ErrNotFound wrapped once",
			err:      fmt.Errorf("entity abc: %w", store.ErrNotFound),
			sentinel: store.ErrNotFound,
		},
		{
			name:     "ErrConflict wrapped once",
			err:      fmt.Errorf("unique constraint: %w", store.ErrConflict),
			sentinel: store.ErrConflict,
		},
		{
			name:     "ErrInvalidInput wrapped once",
			err:      fmt.Errorf("malformed ID: %w", store.ErrInvalidInput),
			sentinel: store.ErrInvalidInput,
		},
		{
			name:     "ErrDatabase wrapped once",
			err:      fmt.Errorf("query failed: %w", store.ErrDatabase),
			sentinel: store.ErrDatabase,
		},
		{
			name:     "ErrNotFound wrapped twice",
			err:      fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", store.ErrNotFound)),
			sentinel: store.ErrNotFound,
		},
		{
			name:     "ErrNotFound with context",
			err:      fmt.Errorf("session sess-123: %w", store.ErrNotFound),
			sentinel: store.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.err, tt.sentinel)
		})
	}
}

// TestSentinelErrors_NotMatching verifies errors.Is returns false for non-matching sentinels.
func TestSentinelErrors_NotMatching(t *testing.T) {
	err := fmt.Errorf("entity abc: %w", store.ErrNotFound)

	// Should NOT match other sentinels
	assert.False(t, errors.Is(err, store.ErrConflict), "ErrNotFound should not match ErrConflict")
	assert.False(t, errors.Is(err, store.ErrInvalidInput), "ErrNotFound should not match ErrInvalidInput")
	assert.False(t, errors.Is(err, store.ErrDatabase), "ErrNotFound should not match ErrDatabase")
}

// TestSentinelErrors_Distinct verifies all sentinels are distinct errors.
func TestSentinelErrors_Distinct(t *testing.T) {
	sentinels := []error{
		store.ErrNotFound,
		store.ErrConflict,
		store.ErrInvalidInput,
		store.ErrDatabase,
	}

	// Ensure no two sentinels are the same
	for i, s1 := range sentinels {
		for j, s2 := range sentinels {
			if i < j {
				assert.NotEqual(t, s1, s2, "sentinels should be distinct")
			}
		}
	}
}

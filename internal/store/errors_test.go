// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// TestSigilErrors_Direct verifies sigilerr errors are classified correctly.
func TestSigilErrors_Direct(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{"NotFound direct", sigilerr.New(sigilerr.CodeStoreEntityNotFound, "not found"), sigilerr.IsNotFound},
		{"Conflict direct", sigilerr.New(sigilerr.CodeStoreConflict, "conflict"), sigilerr.IsConflict},
		{"InvalidInput direct", sigilerr.New(sigilerr.CodeStoreInvalidInput, "invalid input"), sigilerr.IsInvalidInput},
		{"Database direct", sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "database error"), func(err error) bool {
			return sigilerr.HasCode(err, sigilerr.CodeStoreDatabaseFailure)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.check(tt.err))
		})
	}
}

// TestSigilErrors_Wrapped verifies sigilerr errors work when wrapped.
func TestSigilErrors_Wrapped(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{
			name:  "NotFound wrapped",
			err:   sigilerr.Errorf(sigilerr.CodeStoreEntityNotFound, "entity abc: not found"),
			check: sigilerr.IsNotFound,
		},
		{
			name:  "Conflict wrapped",
			err:   sigilerr.Errorf(sigilerr.CodeStoreConflict, "unique constraint: conflict"),
			check: sigilerr.IsConflict,
		},
		{
			name:  "InvalidInput wrapped",
			err:   sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "malformed ID: invalid input"),
			check: sigilerr.IsInvalidInput,
		},
		{
			name: "Database wrapped",
			err:  sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "query failed: database error"),
			check: func(err error) bool {
				return sigilerr.HasCode(err, sigilerr.CodeStoreDatabaseFailure)
			},
		},
		{
			name:  "NotFound with context",
			err:   sigilerr.Errorf(sigilerr.CodeStoreEntityNotFound, "session sess-123: not found"),
			check: sigilerr.IsNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.check(tt.err))
		})
	}
}

// TestSigilErrors_NotMatching verifies classification returns false for non-matching codes.
func TestSigilErrors_NotMatching(t *testing.T) {
	err := sigilerr.New(sigilerr.CodeStoreEntityNotFound, "entity abc: not found")

	// Should NOT match other categories
	assert.False(t, sigilerr.IsConflict(err), "NotFound should not match Conflict")
	assert.False(t, sigilerr.IsInvalidInput(err), "NotFound should not match InvalidInput")
	assert.False(t, sigilerr.HasCode(err, sigilerr.CodeStoreDatabaseFailure), "NotFound should not match Database")
}

// TestSigilErrors_Distinct verifies all error codes are distinct.
func TestSigilErrors_Distinct(t *testing.T) {
	codes := []sigilerr.Code{
		sigilerr.CodeStoreEntityNotFound,
		sigilerr.CodeStoreConflict,
		sigilerr.CodeStoreInvalidInput,
		sigilerr.CodeStoreDatabaseFailure,
	}

	// Ensure no two codes are the same
	for i, c1 := range codes {
		for j, c2 := range codes {
			if i < j {
				assert.NotEqual(t, c1, c2, "error codes should be distinct")
			}
		}
	}
}

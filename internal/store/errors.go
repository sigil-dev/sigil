// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "errors"

// Sentinel errors for store operations.
// These errors can be checked using errors.Is() for classification.
var (
	// ErrNotFound indicates the requested entity does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a conflict occurred (e.g., unique constraint violation,
	// concurrent modification, or entity already exists).
	ErrConflict = errors.New("conflict")

	// ErrInvalidInput indicates the input parameters are invalid or malformed.
	ErrInvalidInput = errors.New("invalid input")

	// ErrDatabase indicates a general database error occurred.
	// This is a catch-all for unexpected database failures.
	ErrDatabase = errors.New("database error")
)

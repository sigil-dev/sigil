// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package scanner export_test.go exposes internal symbols to the external
// scanner_test package during test runs only. This file is compiled exclusively
// when running `go test` and is never included in production binaries.

package scanner

import "sync"

// ResetDBCache resets the package-level sync.Once cache for the embedded
// secrets-patterns-db rules. Call this in TestMain or t.Cleanup to restore
// isolation between tests that exercise loadDBRules with different preconditions.
func ResetDBCache() {
	dbOnce = sync.Once{}
	dbEntries = nil
	dbErr = nil
}

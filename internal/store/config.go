// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

// StorageConfig controls which backend the store factory uses.
type StorageConfig struct {
	Backend          string // "sqlite" is the only supported backend for now.
	VectorDimensions int    // Embedding dimensions; 0 uses the default (1536).
}

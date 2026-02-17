// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package secrets

// Store provides secure secret storage operations.
// Implementations may use OS keyrings, encrypted files, or other backends.
type Store interface {
	// Store saves a secret value under the given service and key.
	Store(service, key, value string) error

	// Retrieve fetches the secret value for the given service and key.
	// Returns ErrSecretNotFound (via sigilerr.HasCode) if the key does not exist.
	Retrieve(service, key string) (string, error)

	// Delete removes the secret for the given service and key.
	// Returns ErrSecretNotFound (via sigilerr.HasCode) if the key does not exist.
	Delete(service, key string) error

	// List returns all key names stored under the given service.
	List(service string) ([]string, error)
}

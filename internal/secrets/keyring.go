// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package secrets

import (
	"encoding/json"
	"errors"
	"log/slog"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/zalando/go-keyring"
)

// keysIndexSuffix is appended to the service name to form the key under which
// the JSON index of stored key names is kept. This allows List() to work despite
// go-keyring not natively supporting key enumeration.
const keysIndexSuffix = "::keys-index"

// KeyringStore implements Store using the OS keyring via zalando/go-keyring.
// On macOS it uses Keychain, on Linux secret-service (D-Bus), and on Windows
// the Credential Manager.
type KeyringStore struct{}

// NewKeyringStore returns a KeyringStore.
func NewKeyringStore() *KeyringStore {
	return &KeyringStore{}
}

func (s *KeyringStore) Store(service, key, value string) error {
	if service == "" {
		return sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret store: service must not be empty")
	}
	if key == "" {
		return sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret store: key must not be empty")
	}

	if err := keyring.Set(service, key, value); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecretStoreFailure, "storing secret %s/%s", service, key)
	}

	if err := s.addToIndex(service, key); err != nil {
		return err
	}

	return nil
}

func (s *KeyringStore) Retrieve(service, key string) (string, error) {
	if service == "" {
		return "", sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret retrieve: service must not be empty")
	}
	if key == "" {
		return "", sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret retrieve: key must not be empty")
	}

	val, err := keyring.Get(service, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", sigilerr.Errorf(sigilerr.CodeSecretNotFound, "secret %s/%s not found", service, key)
		}
		return "", sigilerr.Wrapf(err, sigilerr.CodeSecretStoreFailure, "retrieving secret %s/%s", service, key)
	}
	return val, nil
}

func (s *KeyringStore) Delete(service, key string) error {
	if service == "" {
		return sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret delete: service must not be empty")
	}
	if key == "" {
		return sigilerr.New(sigilerr.CodeSecretInvalidInput, "secret delete: key must not be empty")
	}

	if err := keyring.Delete(service, key); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return sigilerr.Errorf(sigilerr.CodeSecretNotFound, "secret %s/%s not found", service, key)
		}
		return sigilerr.Wrapf(err, sigilerr.CodeSecretDeleteFailure, "deleting secret %s/%s", service, key)
	}

	if err := s.removeFromIndex(service, key); err != nil {
		return err
	}

	return nil
}

func (s *KeyringStore) List(service string) ([]string, error) {
	return s.loadIndex(service)
}

// loadIndex reads the JSON key index for a service from the keyring.
func (s *KeyringStore) loadIndex(service string) ([]string, error) {
	indexKey := service + keysIndexSuffix
	raw, err := keyring.Get(service, indexKey)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil
		}
		return nil, sigilerr.Wrapf(err, sigilerr.CodeSecretListFailure, "loading key index for service %s", service)
	}

	var keys []string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeSecretListFailure, "decoding key index for service %s", service)
	}

	return keys, nil
}

// saveIndex writes the JSON key index for a service to the keyring.
func (s *KeyringStore) saveIndex(service string, keys []string) error {
	indexKey := service + keysIndexSuffix

	if len(keys) == 0 {
		// Clean up the index entry when empty.
		if delErr := keyring.Delete(service, indexKey); delErr != nil {
			slog.Debug("failed to clean up empty key index", "service", service, "error", delErr)
		}
		return nil
	}

	data, err := json.Marshal(keys)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecretListFailure, "encoding key index for service %s", service)
	}

	if err := keyring.Set(service, indexKey, string(data)); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeSecretListFailure, "saving key index for service %s", service)
	}

	return nil
}

// addToIndex adds a key to the service's key index (idempotent).
func (s *KeyringStore) addToIndex(service, key string) error {
	keys, err := s.loadIndex(service)
	if err != nil {
		return err
	}

	for _, k := range keys {
		if k == key {
			return nil // already present
		}
	}

	keys = append(keys, key)
	return s.saveIndex(service, keys)
}

// removeFromIndex removes a key from the service's key index.
func (s *KeyringStore) removeFromIndex(service, key string) error {
	keys, err := s.loadIndex(service)
	if err != nil {
		return err
	}

	filtered := keys[:0]
	for _, k := range keys {
		if k != key {
			filtered = append(filtered, k)
		}
	}

	return s.saveIndex(service, filtered)
}

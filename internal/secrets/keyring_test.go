// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package secrets_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func init() {
	// Use the mock keyring for all tests so they don't touch the real OS keyring.
	keyring.MockInit()
}

func TestKeyringStore_StoreAndRetrieve(t *testing.T) {
	ks := secrets.NewKeyringStore()
	svc := "test-store-retrieve"

	err := ks.Store(svc, "api-key", "sk-secret-123")
	require.NoError(t, err)

	val, err := ks.Retrieve(svc, "api-key")
	require.NoError(t, err)
	assert.Equal(t, "sk-secret-123", val)
}

func TestKeyringStore_RetrieveNotFound(t *testing.T) {
	ks := secrets.NewKeyringStore()

	_, err := ks.Retrieve("no-such-service", "no-key")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecretNotFound), "expected CodeSecretNotFound, got: %v", err)
}

func TestKeyringStore_Delete(t *testing.T) {
	ks := secrets.NewKeyringStore()
	svc := "test-delete"

	err := ks.Store(svc, "temp-key", "temp-value")
	require.NoError(t, err)

	err = ks.Delete(svc, "temp-key")
	require.NoError(t, err)

	_, err = ks.Retrieve(svc, "temp-key")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecretNotFound))
}

func TestKeyringStore_DeleteNotFound(t *testing.T) {
	ks := secrets.NewKeyringStore()

	err := ks.Delete("no-such-service", "no-key")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecretNotFound), "expected CodeSecretNotFound, got: %v", err)
}

func TestKeyringStore_List(t *testing.T) {
	ks := secrets.NewKeyringStore()
	svc := "test-list"

	// Initially empty.
	keys, err := ks.List(svc)
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Store multiple keys.
	require.NoError(t, ks.Store(svc, "key-a", "val-a"))
	require.NoError(t, ks.Store(svc, "key-b", "val-b"))
	require.NoError(t, ks.Store(svc, "key-c", "val-c"))

	keys, err = ks.List(svc)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"key-a", "key-b", "key-c"}, keys)
}

func TestKeyringStore_ListAfterDelete(t *testing.T) {
	ks := secrets.NewKeyringStore()
	svc := "test-list-delete"

	require.NoError(t, ks.Store(svc, "key-x", "val"))
	require.NoError(t, ks.Store(svc, "key-y", "val"))
	require.NoError(t, ks.Delete(svc, "key-x"))

	keys, err := ks.List(svc)
	require.NoError(t, err)
	assert.Equal(t, []string{"key-y"}, keys)
}

func TestKeyringStore_StoreOverwrite(t *testing.T) {
	ks := secrets.NewKeyringStore()
	svc := "test-overwrite"

	require.NoError(t, ks.Store(svc, "key", "old-value"))
	require.NoError(t, ks.Store(svc, "key", "new-value"))

	val, err := ks.Retrieve(svc, "key")
	require.NoError(t, err)
	assert.Equal(t, "new-value", val)

	// List should not duplicate the key.
	keys, err := ks.List(svc)
	require.NoError(t, err)
	assert.Equal(t, []string{"key"}, keys)
}

func TestKeyringStore_StoreEmptyInputs(t *testing.T) {
	ks := secrets.NewKeyringStore()

	tests := []struct {
		name    string
		service string
		key     string
		value   string
	}{
		{"empty service", "", "key", "val"},
		{"empty key", "svc", "", "val"},
		{"empty value", "svc", "key", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ks.Store(tt.service, tt.key, tt.value)
			if tt.value == "" {
				// Empty value is allowed (stores empty string).
				assert.NoError(t, err)
			} else if tt.service == "" || tt.key == "" {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecretInvalidInput))
			}
		})
	}
}

func TestKeyringStore_ImplementsStoreInterface(t *testing.T) {
	var _ secrets.Store = secrets.NewKeyringStore()
}

func TestKeyringStore_IsolatedServices(t *testing.T) {
	ks := secrets.NewKeyringStore()

	require.NoError(t, ks.Store("svc-a", "shared-key", "value-a"))
	require.NoError(t, ks.Store("svc-b", "shared-key", "value-b"))

	valA, err := ks.Retrieve("svc-a", "shared-key")
	require.NoError(t, err)
	assert.Equal(t, "value-a", valA)

	valB, err := ks.Retrieve("svc-b", "shared-key")
	require.NoError(t, err)
	assert.Equal(t, "value-b", valB)

	keysA, err := ks.List("svc-a")
	require.NoError(t, err)
	assert.Equal(t, []string{"shared-key"}, keysA)
}

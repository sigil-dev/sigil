// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretStore is an in-memory secrets.Store for testing.
type mockSecretStore struct {
	data map[string]string // key → value (service is always "sigil")
}

func newMockSecretStore(keys ...string) *mockSecretStore {
	m := &mockSecretStore{data: make(map[string]string)}
	for _, k := range keys {
		m.data[k] = "redacted"
	}
	return m
}

func (m *mockSecretStore) Store(_, key, value string) error {
	m.data[key] = value
	return nil
}

func (m *mockSecretStore) Retrieve(_, key string) (string, error) {
	v, ok := m.data[key]
	if !ok {
		return "", sigilerr.Errorf(sigilerr.CodeSecretNotFound, "not found")
	}
	return v, nil
}

func (m *mockSecretStore) Delete(_, key string) error {
	if _, ok := m.data[key]; !ok {
		return sigilerr.Errorf(sigilerr.CodeSecretNotFound, "not found")
	}
	delete(m.data, key)
	return nil
}

func (m *mockSecretStore) List(_ string) ([]string, error) {
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestSecretList(t *testing.T) {
	tests := []struct {
		name     string
		keys     []string
		wantKeys []string // expected keys in output (sorted for comparison)
		wantMsg  string   // exact output for empty case
	}{
		{
			name:    "empty store",
			keys:    nil,
			wantMsg: "No secrets stored.\n",
		},
		{
			name:     "single key",
			keys:     []string{"anthropic-api-key"},
			wantKeys: []string{"anthropic-api-key"},
		},
		{
			name:     "multiple keys",
			keys:     []string{"api-key-1", "api-key-2"},
			wantKeys: []string{"api-key-1", "api-key-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockSecretStore(tt.keys...)
			origFactory := secretStoreFactory
			secretStoreFactory = func() secrets.Store { return mock }
			t.Cleanup(func() { secretStoreFactory = origFactory })

			cmd := NewRootCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"secret", "list"})

			err := cmd.Execute()
			require.NoError(t, err)

			if tt.wantMsg != "" {
				assert.Equal(t, tt.wantMsg, buf.String())
			} else {
				// Sort output lines for deterministic comparison (map iteration order).
				got := strings.Split(strings.TrimSpace(buf.String()), "\n")
				sort.Strings(got)
				want := append([]string(nil), tt.wantKeys...)
				sort.Strings(want)
				assert.Equal(t, want, got)
			}
		})
	}
}

func TestSecretDelete(t *testing.T) {
	tests := []struct {
		name       string
		keys       []string
		deleteKey  string
		wantOutput string
		wantErr    bool
		wantCode   sigilerr.Code
	}{
		{
			name:       "delete existing key",
			keys:       []string{"anthropic-api-key"},
			deleteKey:  "anthropic-api-key",
			wantOutput: "Deleted secret: anthropic-api-key\n",
		},
		{
			name:      "delete non-existent key",
			keys:      nil,
			deleteKey: "missing-key",
			wantErr:   true,
			wantCode:  sigilerr.CodeSecretNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockSecretStore(tt.keys...)
			origFactory := secretStoreFactory
			secretStoreFactory = func() secrets.Store { return mock }
			t.Cleanup(func() { secretStoreFactory = origFactory })

			cmd := NewRootCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"secret", "delete", tt.deleteKey})

			err := cmd.Execute()

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.wantCode),
					"expected error code %s, got: %v", tt.wantCode, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantOutput, buf.String())
			}
		})
	}
}

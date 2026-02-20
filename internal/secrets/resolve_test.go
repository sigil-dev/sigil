// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package secrets_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKeyringURI(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"valid URI", "keyring://sigil/anthropic-api-key", true},
		{"valid URI with dashes", "keyring://my-svc/my-key", true},
		{"env var reference", "${ANTHROPIC_API_KEY}", false},
		{"literal value", "sk-abc123", false},
		{"empty string", "", false},
		{"just scheme", "keyring://", true},
		{"other scheme", "vault://secret/key", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secrets.IsKeyringURI(tt.value)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseKeyringURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantService string
		wantKey     string
		wantErr     bool
	}{
		{"valid", "keyring://sigil/api-key", "sigil", "api-key", false},
		{"dashes", "keyring://my-service/my-key-name", "my-service", "my-key-name", false},
		{"slashes in key", "keyring://sigil/path/to/key", "sigil", "path/to/key", false},
		{"not a keyring URI", "vault://secret/key", "", "", true},
		{"missing key", "keyring://sigil/", "", "", true},
		{"missing service", "keyring:///key", "", "", true},
		{"missing both", "keyring://", "", "", true},
		{"no path", "keyring://sigil", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, key, err := secrets.ParseKeyringURI(tt.uri)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeSecretInvalidInput))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantService, svc)
				assert.Equal(t, tt.wantKey, key)
			}
		})
	}
}

func TestResolveKeyringURI(t *testing.T) {
	ks := secrets.NewKeyringStore()
	require.NoError(t, ks.Store("sigil", "test-key", "resolved-secret"))

	t.Run("resolves keyring URI", func(t *testing.T) {
		val, err := secrets.ResolveKeyringURI(ks, "keyring://sigil/test-key")
		require.NoError(t, err)
		assert.Equal(t, "resolved-secret", val)
	})

	t.Run("passes through non-keyring values", func(t *testing.T) {
		val, err := secrets.ResolveKeyringURI(ks, "literal-value")
		require.NoError(t, err)
		assert.Equal(t, "literal-value", val)
	})

	t.Run("passes through env var references", func(t *testing.T) {
		val, err := secrets.ResolveKeyringURI(ks, "${ENV_VAR}")
		require.NoError(t, err)
		assert.Equal(t, "${ENV_VAR}", val)
	})

	t.Run("error on missing secret", func(t *testing.T) {
		_, err := secrets.ResolveKeyringURI(ks, "keyring://sigil/nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving keyring URI")
	})

	t.Run("error on malformed URI", func(t *testing.T) {
		_, err := secrets.ResolveKeyringURI(ks, "keyring://bad")
		require.Error(t, err)
	})
}

func TestResolveViperSecrets(t *testing.T) {
	ks := secrets.NewKeyringStore()
	require.NoError(t, ks.Store("sigil", "anthropic-api-key", "sk-ant-secret"))
	require.NoError(t, ks.Store("sigil", "openai-api-key", "sk-oai-secret"))

	v := viper.New()
	v.Set("providers.anthropic.api_key", "keyring://sigil/anthropic-api-key")
	v.Set("providers.openai.api_key", "keyring://sigil/openai-api-key")
	v.Set("networking.listen", "127.0.0.1:18789") // non-keyring value
	v.Set("models.default", "anthropic/claude-sonnet-4-5")

	require.NoError(t, secrets.ResolveViperSecrets(v, ks))

	assert.Equal(t, "sk-ant-secret", v.GetString("providers.anthropic.api_key"))
	assert.Equal(t, "sk-oai-secret", v.GetString("providers.openai.api_key"))
	assert.Equal(t, "127.0.0.1:18789", v.GetString("networking.listen"))
	assert.Equal(t, "anthropic/claude-sonnet-4-5", v.GetString("models.default"))
}

func TestResolveViperSecrets_MissingSecretReturnsError(t *testing.T) {
	ks := secrets.NewKeyringStore()

	v := viper.New()
	v.Set("providers.anthropic.api_key", "keyring://sigil/nonexistent-key")

	err := secrets.ResolveViperSecrets(v, ks)

	// Should return an error with a clear message identifying the unresolved key.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "providers.anthropic.api_key")
	assert.Contains(t, err.Error(), "keyring://sigil/nonexistent-key")
}

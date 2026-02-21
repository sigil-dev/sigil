// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretStore is an in-memory secrets.Store for testing.
type mockSecretStore struct {
	data map[string]map[string]string
	err  error // if non-nil, all operations return this error
}

func newMockSecretStore() *mockSecretStore {
	return &mockSecretStore{data: make(map[string]map[string]string)}
}

func (m *mockSecretStore) Store(service, key, value string) error {
	if m.err != nil {
		return m.err
	}
	if m.data[service] == nil {
		m.data[service] = make(map[string]string)
	}
	m.data[service][key] = value
	return nil
}

func (m *mockSecretStore) Retrieve(service, key string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if svc, ok := m.data[service]; ok {
		if val, ok := svc[key]; ok {
			return val, nil
		}
	}
	return "", sigilerr.Errorf(sigilerr.CodeSecretNotFound, "not found")
}

func (m *mockSecretStore) Delete(service, key string) error {
	if m.err != nil {
		return m.err
	}
	if svc, ok := m.data[service]; ok {
		delete(svc, key)
	}
	return nil
}

func (m *mockSecretStore) List(service string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if svc, ok := m.data[service]; ok {
		keys := make([]string, 0, len(svc))
		for k := range svc {
			keys = append(keys, k)
		}
		return keys, nil
	}
	return nil, nil
}

func newTestServerWithConfig(t *testing.T, deps *server.ConfigDeps) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		ConfigDeps: deps,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestConfigureProvider_Success(t *testing.T) {
	secrets := newMockSecretStore()
	deps := &server.ConfigDeps{
		Secrets: secrets,
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "anthropic", "api_key": "sk-ant-test-key-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "anthropic", resp.Provider)

	// Verify key was stored in keyring
	stored, err := secrets.Retrieve("sigil", "anthropic-api-key")
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-test-key-123", stored)
}

func TestConfigureProvider_InvalidKey(t *testing.T) {
	deps := &server.ConfigDeps{
		Secrets: newMockSecretStore(),
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return sigilerr.Errorf(sigilerr.CodeProviderKeyInvalid, "invalid key")
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "openai", "api_key": "bad-key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid openai API key")
}

func TestConfigureProvider_ValidationCheckFailed(t *testing.T) {
	deps := &server.ConfigDeps{
		Secrets: newMockSecretStore(),
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "network error")
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "google", "api_key": "some-key-value-12345678901234"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "could not validate google API key")
}

func TestConfigureProvider_MissingFields(t *testing.T) {
	deps := &server.ConfigDeps{
		Secrets: newMockSecretStore(),
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	// Missing api_key
	body := `{"type": "anthropic"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestConfigureProvider_NoDeps(t *testing.T) {
	srv := newTestServerWithConfig(t, nil)

	body := `{"type": "anthropic", "api_key": "sk-ant-test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestConfigureChannel_Success(t *testing.T) {
	secrets := newMockSecretStore()
	deps := &server.ConfigDeps{
		Secrets: secrets,
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "telegram", "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Status  string `json:"status"`
		Channel string `json:"channel"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "telegram", resp.Channel)

	// Verify token was stored in keyring
	stored, err := secrets.Retrieve("sigil", "telegram-bot-token")
	require.NoError(t, err)
	assert.Equal(t, "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", stored)
}

func TestConfigureChannel_InvalidToken(t *testing.T) {
	deps := &server.ConfigDeps{
		Secrets: newMockSecretStore(),
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return sigilerr.Errorf(sigilerr.CodeChannelTokenInvalid, "invalid token")
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "telegram", "bot_token": "bad-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid telegram bot token")
}

func TestConfigureChannel_ValidationCheckFailed(t *testing.T) {
	deps := &server.ConfigDeps{
		Secrets: newMockSecretStore(),
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "telegram API unreachable")
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "telegram", "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "could not validate telegram bot token")
}

func TestConfigureChannel_NoDeps(t *testing.T) {
	srv := newTestServerWithConfig(t, nil)

	body := `{"type": "telegram", "bot_token": "123:ABC"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestConfigureProvider_KeyringStoreError(t *testing.T) {
	secrets := newMockSecretStore()
	secrets.err = sigilerr.Errorf(sigilerr.CodeSecretStoreFailure, "keyring locked")
	deps := &server.ConfigDeps{
		Secrets: secrets,
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "anthropic", "api_key": "sk-ant-valid-key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to store API key")
}

func TestConfigureChannel_KeyringStoreError(t *testing.T) {
	secrets := newMockSecretStore()
	secrets.err = sigilerr.Errorf(sigilerr.CodeSecretStoreFailure, "keyring locked")
	deps := &server.ConfigDeps{
		Secrets: secrets,
		ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
			return nil
		},
		ValidateChannel: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	srv := newTestServerWithConfig(t, deps)

	body := `{"type": "telegram", "bot_token": "123:ABC-valid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to store bot token")
}

func TestConfigureProvider_AllProviderTypes(t *testing.T) {
	providerTypes := []string{"anthropic", "openai", "google", "openrouter"}

	for _, pt := range providerTypes {
		t.Run(pt, func(t *testing.T) {
			secrets := newMockSecretStore()
			deps := &server.ConfigDeps{
				Secrets: secrets,
				ValidateProvider: func(_ context.Context, _ provider.ProviderName, _ string) error {
					return nil
				},
				ValidateChannel: func(_ context.Context, _, _ string) error {
					return nil
				},
			}
			srv := newTestServerWithConfig(t, deps)

			body := `{"type": "` + pt + `", "api_key": "test-key-for-` + pt + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/config/providers", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			stored, err := secrets.Retrieve("sigil", pt+"-api-key")
			require.NoError(t, err)
			assert.Equal(t, "test-key-for-"+pt, stored)
		})
	}
}

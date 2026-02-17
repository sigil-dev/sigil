// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateKey_Anthropic_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "test-api-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	}))
	defer srv.Close()

	err := ValidateKeyWithURL(context.Background(), srv.Client(), ProviderAnthropic, "test-api-key", srv.URL+"/v1/models", nil)
	require.NoError(t, err)
}

func TestValidateKey_InvalidKey_ReturnsError(t *testing.T) {
	tests := []struct {
		name       string
		provider   ProviderName
		statusCode int
		wantCode   sigilerr.Code
	}{
		{
			name:       "anthropic 401",
			provider:   ProviderAnthropic,
			statusCode: http.StatusUnauthorized,
			wantCode:   sigilerr.CodeProviderKeyInvalid,
		},
		{
			name:       "openai 403",
			provider:   ProviderOpenAI,
			statusCode: http.StatusForbidden,
			wantCode:   sigilerr.CodeProviderKeyInvalid,
		},
		{
			name:       "google 401",
			provider:   ProviderGoogle,
			statusCode: http.StatusUnauthorized,
			wantCode:   sigilerr.CodeProviderKeyInvalid,
		},
		{
			name:       "openrouter 500",
			provider:   ProviderOpenRouter,
			statusCode: http.StatusInternalServerError,
			wantCode:   sigilerr.CodeProviderKeyCheckFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			err := ValidateKeyWithURL(context.Background(), srv.Client(), tt.provider, "bad-key", srv.URL+"/v1/models", nil)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
		})
	}
}

func TestValidateKey_UnknownProvider(t *testing.T) {
	err := ValidateKeyWithURL(context.Background(), http.DefaultClient, "unknown", "key", "", nil)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeProviderKeyInvalid))
}

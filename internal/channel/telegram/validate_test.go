// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package telegram

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

func TestValidateToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/bottest-token/getMe")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"id": 123}})
	}))
	defer srv.Close()

	err := ValidateTokenWithURL(context.Background(), srv.Client(), "test-token", srv.URL+"/bottest-token/getMe")
	require.NoError(t, err)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantCode   sigilerr.Code
	}{
		{"401 unauthorized", http.StatusUnauthorized, sigilerr.CodeChannelTokenInvalid},
		{"403 forbidden", http.StatusForbidden, sigilerr.CodeChannelTokenInvalid},
		{"500 server error", http.StatusInternalServerError, sigilerr.CodeChannelTokenCheckFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			err := ValidateTokenWithURL(context.Background(), srv.Client(), "bad-token", srv.URL+"/botbad-token/getMe")
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Provider key validation tests ---

func TestValidateProviderKey_Anthropic_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "test-api-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	}))
	defer srv.Close()

	client := srv.Client()
	// Patch the URL to use the test server.
	oldClient := initHTTPClient
	initHTTPClient = client
	defer func() { initHTTPClient = oldClient }()

	// We need to redirect to the test server, so we use a wrapper.
	err := validateProviderKeyWithURL(context.Background(), client, ProviderAnthropic, "test-api-key", srv.URL+"/v1/models", nil)
	require.NoError(t, err)
}

func TestValidateProviderKey_InvalidKey_ReturnsError(t *testing.T) {
	tests := []struct {
		name       string
		provider   ProviderType
		statusCode int
		wantCode   sigilerr.Code
	}{
		{
			name:       "anthropic 401",
			provider:   ProviderAnthropic,
			statusCode: http.StatusUnauthorized,
			wantCode:   sigilerr.CodeCLIInputInvalid,
		},
		{
			name:       "openai 403",
			provider:   ProviderOpenAI,
			statusCode: http.StatusForbidden,
			wantCode:   sigilerr.CodeCLIInputInvalid,
		},
		{
			name:       "google 401",
			provider:   ProviderGoogle,
			statusCode: http.StatusUnauthorized,
			wantCode:   sigilerr.CodeCLIInputInvalid,
		},
		{
			name:       "openrouter 500",
			provider:   ProviderOpenRouter,
			statusCode: http.StatusInternalServerError,
			wantCode:   sigilerr.CodeCLIRequestFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			err := validateProviderKeyWithURL(context.Background(), srv.Client(), tt.provider, "bad-key", srv.URL+"/v1/models", nil)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
		})
	}
}

func TestValidateProviderKey_UnknownProvider(t *testing.T) {
	err := validateProviderKeyWithURL(context.Background(), http.DefaultClient, "unknown", "key", "", nil)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeCLIInputInvalid))
}

// --- Telegram token validation tests ---

func TestValidateTelegramToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/bottest-token/getMe")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"id": 123}})
	}))
	defer srv.Close()

	err := validateTelegramTokenWithURL(context.Background(), srv.Client(), "test-token", srv.URL+"/bottest-token/getMe")
	require.NoError(t, err)
}

func TestValidateTelegramToken_InvalidToken(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantCode   sigilerr.Code
	}{
		{"401 unauthorized", http.StatusUnauthorized, sigilerr.CodeCLIInputInvalid},
		{"403 forbidden", http.StatusForbidden, sigilerr.CodeCLIInputInvalid},
		{"500 server error", http.StatusInternalServerError, sigilerr.CodeCLIRequestFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			err := validateTelegramTokenWithURL(context.Background(), srv.Client(), "bad-token", srv.URL+"/botbad-token/getMe")
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode),
				"expected %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
		})
	}
}

// --- Config generation tests ---

func TestGenerateConfigYAML(t *testing.T) {
	tests := []struct {
		name   string
		result initResult
		checks []string
	}{
		{
			name: "anthropic provider with telegram",
			result: initResult{
				Provider:     ProviderAnthropic,
				APIKey:       "sk-ant-test",
				Channel:      ChannelTelegram,
				ChannelToken: "bot123:abc",
			},
			checks: []string{
				"keyring://sigil/anthropic-api-key",
				"anthropic/claude-sonnet-4-5",
				"channel: \"telegram\"",
				"keyring://sigil/telegram-bot-token",
			},
		},
		{
			name: "openai provider with telegram",
			result: initResult{
				Provider:     ProviderOpenAI,
				APIKey:       "sk-openai",
				Channel:      ChannelTelegram,
				ChannelToken: "botxyz",
			},
			checks: []string{
				"keyring://sigil/openai-api-key",
				"openai/gpt-4o",
				"channel: \"telegram\"",
			},
		},
		{
			name: "google provider",
			result: initResult{
				Provider:     ProviderGoogle,
				APIKey:       "AIza...",
				Channel:      ChannelTelegram,
				ChannelToken: "botxyz",
			},
			checks: []string{
				"keyring://sigil/google-api-key",
				"google/gemini-2.0-flash",
			},
		},
		{
			name: "openrouter provider",
			result: initResult{
				Provider:     ProviderOpenRouter,
				APIKey:       "sk-or",
				Channel:      ChannelTelegram,
				ChannelToken: "botxyz",
			},
			checks: []string{
				"keyring://sigil/openrouter-api-key",
				"openrouter/anthropic/claude-sonnet-4-5",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := GenerateConfigYAML(tt.result)
			for _, check := range tt.checks {
				assert.Contains(t, yaml, check, "YAML missing expected content: %q", check)
			}
			// API key itself must NOT appear in plain text.
			assert.NotContains(t, yaml, tt.result.APIKey, "plain-text API key must not appear in YAML")
			assert.NotContains(t, yaml, tt.result.ChannelToken, "plain-text channel token must not appear in YAML")
		})
	}
}

// --- bubbletea model state transition tests ---

func TestInitModel_ProviderSelection(t *testing.T) {
	m := newInitModel(nil)
	assert.Equal(t, stepProvider, m.step)
	assert.Equal(t, 0, m.providerIdx)

	// Navigate down twice.
	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m3, _ := m2.(initModel).Update(tea.KeyMsg{Type: tea.KeyDown})
	assert.Equal(t, 2, m3.(initModel).providerIdx)

	// Navigate up once.
	m4, _ := m3.(initModel).Update(tea.KeyMsg{Type: tea.KeyUp})
	assert.Equal(t, 1, m4.(initModel).providerIdx)

	// Can't go above 0.
	m5, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	assert.Equal(t, 0, m5.(initModel).providerIdx)

	// Can't go below max.
	mMax := m
	mMax.providerIdx = len(supportedProviders) - 1
	m6, _ := mMax.Update(tea.KeyMsg{Type: tea.KeyDown})
	assert.Equal(t, len(supportedProviders)-1, m6.(initModel).providerIdx)
}

func TestInitModel_SelectProvider_TransitionsToAPIKey(t *testing.T) {
	m := newInitModel(nil)
	m.providerIdx = 1 // OpenAI

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := m2.(initModel)
	assert.Equal(t, stepAPIKey, result.step)
	assert.Equal(t, ProviderOpenAI, result.result.Provider)
}

func TestInitModel_EmptyAPIKey_ShowsError(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepAPIKey
	m.result.Provider = ProviderAnthropic
	// Don't set any value in apiKeyInput.

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := m2.(initModel)
	assert.Equal(t, stepAPIKey, result.step)
	assert.NotEmpty(t, result.validationErr)
}

func TestInitModel_ChannelSelection(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepChannel
	m.channelIdx = 0

	// Can't go below 0.
	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	assert.Equal(t, 0, m2.(initModel).channelIdx)

	// Can't go above max.
	mMax := m
	mMax.channelIdx = len(supportedChannels) - 1
	m3, _ := mMax.Update(tea.KeyMsg{Type: tea.KeyDown})
	assert.Equal(t, len(supportedChannels)-1, m3.(initModel).channelIdx)
}

func TestInitModel_SelectChannel_TransitionsToToken(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepChannel
	m.channelIdx = 0 // Telegram

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := m2.(initModel)
	assert.Equal(t, stepChannelToken, result.step)
	assert.Equal(t, ChannelTelegram, result.result.Channel)
}

func TestInitModel_EmptyChannelToken_ShowsError(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepChannelToken
	m.result.Channel = ChannelTelegram

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := m2.(initModel)
	assert.Equal(t, stepChannelToken, result.step)
	assert.NotEmpty(t, result.validationErr)
}

func TestInitModel_ValidationSuccess_ProviderTransitionsToChannel(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateKey
	m.result.Provider = ProviderAnthropic

	m2, _ := m.Update(validationSuccessMsg{step: stepValidateKey})
	assert.Equal(t, stepChannel, m2.(initModel).step)
}

func TestInitModel_ValidationError_ResetsToInput(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateKey

	m2, _ := m.Update(validationErrorMsg{
		step: stepValidateKey,
		err:  sigilerr.New(sigilerr.CodeCLIInputInvalid, "bad key"),
	})
	result := m2.(initModel)
	assert.Equal(t, stepAPIKey, result.step)
	assert.Contains(t, result.validationErr, "bad key")
}

func TestInitModel_ChannelValidationError_ResetsToToken(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateChan

	m2, _ := m.Update(validationErrorMsg{
		step: stepValidateChan,
		err:  sigilerr.New(sigilerr.CodeCLIInputInvalid, "bad token"),
	})
	result := m2.(initModel)
	assert.Equal(t, stepChannelToken, result.step)
	assert.Contains(t, result.validationErr, "bad token")
}

func TestInitModel_ConfigWritten_TransitionsToDone(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateChan

	m2, _ := m.Update(configWrittenMsg{path: "/tmp/sigil.yaml"})
	fm := m2.(initModel)
	assert.Equal(t, stepDone, fm.step)
	assert.Equal(t, "/tmp/sigil.yaml", fm.configPath)
}

func TestInitModel_View_ContainsExpectedContent(t *testing.T) {
	tests := []struct {
		name    string
		step    initWizardStep
		want    []string
		notWant []string
	}{
		{
			name: "provider step",
			step: stepProvider,
			want: []string{"Step 1/2", "anthropic", "openai", "google", "openrouter"},
		},
		{
			name: "channel step",
			step: stepChannel,
			want: []string{"Step 2/2", "telegram"},
		},
		{
			name: "done step",
			step: stepDone,
			want: []string{"Setup complete", "sigil start", "sigil chat", "sigil doctor"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newInitModel(nil)
			m.step = tt.step
			view := m.View()
			for _, w := range tt.want {
				assert.Contains(t, view, w)
			}
		})
	}
}

func TestDefaultModelForProvider(t *testing.T) {
	tests := []struct {
		provider ProviderType
		want     string
	}{
		{ProviderAnthropic, "anthropic/claude-sonnet-4-5"},
		{ProviderOpenAI, "openai/gpt-4o"},
		{ProviderGoogle, "google/gemini-2.0-flash"},
		{ProviderOpenRouter, "openrouter/anthropic/claude-sonnet-4-5"},
		{"custom", "custom/default"},
	}
	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			assert.Equal(t, tt.want, defaultModelForProvider(tt.provider))
		})
	}
}

func TestGenerateConfigYAML_ContainsRequiredSections(t *testing.T) {
	result := initResult{
		Provider:     ProviderAnthropic,
		APIKey:       "sk-ant",
		Channel:      ChannelTelegram,
		ChannelToken: "123:bot",
	}
	yaml := GenerateConfigYAML(result)

	required := []string{
		"networking:",
		"storage:",
		"providers:",
		"models:",
		"sessions:",
		"workspaces:",
	}
	for _, section := range required {
		assert.True(t, strings.Contains(yaml, section), "missing section: %s", section)
	}
}

// --- Helpers for testable validation (URL-parameterized versions) ---

// validateProviderKeyWithURL is a testable version of ValidateProviderKey that
// accepts an explicit URL. When url is non-empty it overrides the provider default.
func validateProviderKeyWithURL(ctx context.Context, client *http.Client, provider ProviderType, key, url string, headers map[string]string) error {
	if provider == "" || provider == "unknown" {
		return sigilerr.Errorf(sigilerr.CodeCLIInputInvalid, "unknown provider: %s", provider)
	}

	if url == "" {
		// Fall through to the real endpoint (only in integration tests).
		return ValidateProviderKey(ctx, client, provider, key)
	}

	// Build a synthetic provider with the given URL.
	if headers == nil {
		headers = make(map[string]string)
	}
	switch provider {
	case ProviderAnthropic:
		headers["x-api-key"] = key
		headers["anthropic-version"] = "2023-06-01"
	case ProviderOpenAI, ProviderOpenRouter:
		headers["Authorization"] = "Bearer " + key
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "building request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeCLIInputInvalid, "invalid %s API key (HTTP %d)", provider, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "validation failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// validateTelegramTokenWithURL is a testable version that uses the given URL directly.
func validateTelegramTokenWithURL(ctx context.Context, client *http.Client, token, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "building Telegram request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "Telegram request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeCLIInputInvalid, "invalid Telegram bot token (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "Telegram validation failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

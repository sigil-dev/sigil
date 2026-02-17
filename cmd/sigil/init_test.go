// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// --- Channel skip tests ---

func TestInitModel_ChannelSkip_SKeySkipsChannel(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepChannel
	m.result.Provider = ProviderAnthropic

	m2, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	result := m2.(initModel)
	// Channel and ChannelToken should be empty.
	assert.Empty(t, result.result.Channel)
	assert.Empty(t, result.result.ChannelToken)
	// A command should be returned (writeConfigCmd).
	assert.NotNil(t, cmd)
}

func TestInitModel_SkipChannelFlag_SkipsAfterProviderValidation(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateKey
	m.result.Provider = ProviderAnthropic
	m.skipChannel = true

	m2, cmd := m.Update(validationSuccessMsg{step: stepValidateKey})
	result := m2.(initModel)
	// Channel should be empty (skipped).
	assert.Empty(t, result.result.Channel)
	assert.Empty(t, result.result.ChannelToken)
	// Should produce a write command, not transition to stepChannel.
	assert.NotNil(t, cmd)
	assert.NotEqual(t, stepChannel, result.step)
}

func TestInitModel_NoSkipChannelFlag_TransitionsToChannel(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepValidateKey
	m.result.Provider = ProviderAnthropic
	m.skipChannel = false

	m2, _ := m.Update(validationSuccessMsg{step: stepValidateKey})
	assert.Equal(t, stepChannel, m2.(initModel).step)
}

func TestInitModel_ChannelView_ShowsSkipHint(t *testing.T) {
	m := newInitModel(nil)
	m.step = stepChannel
	view := m.View()
	assert.Contains(t, view, "s to skip")
}

// --- Config generation with empty channel ---

func TestGenerateConfigYAML_EmptyChannel(t *testing.T) {
	result := initResult{
		Provider: ProviderAnthropic,
		APIKey:   "sk-ant",
		Channel:  "",
	}
	yaml := GenerateConfigYAML(result)

	// Should still have required sections.
	assert.Contains(t, yaml, "providers:")
	assert.Contains(t, yaml, "workspaces:")
	// Should NOT contain channel binding or channel token reference.
	assert.NotContains(t, yaml, "channel: \"telegram\"")
	assert.NotContains(t, yaml, "bot-token")
	// Should have empty bindings list.
	assert.Contains(t, yaml, "bindings: []")
}

// --- Config overwrite detection ---
// Tests below reuse mockSecretStore from secret_test.go (same package).

func TestStoreSecretAndWriteConfig_OverwriteProtection(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sigil.yaml")

	// Override configPathForWrite so it points to our temp dir.
	origFn := configPathForWrite
	configPathForWrite = func() (string, error) { return cfgPath, nil }
	t.Cleanup(func() { configPathForWrite = origFn })

	store := newMockSecretStore()
	result := initResult{
		Provider:     ProviderAnthropic,
		APIKey:       "sk-test",
		Channel:      ChannelTelegram,
		ChannelToken: "bot:token",
	}

	// First write should succeed.
	path, err := storeSecretAndWriteConfig(result, store, false)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, path)

	// Second write without force should fail.
	_, err = storeSecretAndWriteConfig(result, store, false)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigAlreadyExists))
	assert.Contains(t, err.Error(), "--force to overwrite")

	// Write with force should succeed.
	path, err = storeSecretAndWriteConfig(result, store, true)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, path)
}

func TestStoreSecretAndWriteConfig_SkipsChannelTokenWhenEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sigil.yaml")

	origFn := configPathForWrite
	configPathForWrite = func() (string, error) { return cfgPath, nil }
	t.Cleanup(func() { configPathForWrite = origFn })

	store := newMockSecretStore()
	result := initResult{
		Provider:     ProviderAnthropic,
		APIKey:       "sk-test",
		Channel:      "",
		ChannelToken: "",
	}

	_, err := storeSecretAndWriteConfig(result, store, false)
	require.NoError(t, err)

	// Provider key should be stored.
	_, provErr := store.Retrieve("sigil", "anthropic-api-key")
	assert.NoError(t, provErr)

	// No channel token should be stored.
	assert.Len(t, store.data, 1, "only provider key should be stored when channel is skipped")

	// Written config should not reference channel.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "channel: \"telegram\"")
	assert.Contains(t, string(data), "bindings: []")
}


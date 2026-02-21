// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/pkg/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultValues(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:18789", cfg.Networking.Listen)
	assert.Equal(t, "local", cfg.Networking.Mode)
	assert.True(t, cfg.Networking.ChatRateLimitEnabled)
	assert.Equal(t, 30, cfg.Networking.ChatRateLimitRPM)
	assert.Equal(t, 10, cfg.Networking.ChatRateLimitBurst)
	assert.Equal(t, 5, cfg.Networking.ChatMaxConcurrentStreams)
	assert.Equal(t, "sqlite", cfg.Storage.Backend)
	assert.Equal(t, 20, cfg.Sessions.Memory.ActiveWindow)
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sigil.yaml")

	content := `
networking:
  listen: "0.0.0.0:9999"
models:
  default: "openai/gpt-4.1"
providers:
  openai:
    api_key: "test-key"
`
	err := os.WriteFile(cfgPath, []byte(content), 0o644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9999", cfg.Networking.Listen)
	assert.Equal(t, "openai/gpt-4.1", cfg.Models.Default)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("SIGIL_NETWORKING_LISTEN", "10.0.0.1:8080")

	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:8080", cfg.Networking.Listen)
}

func TestLoad_ValidationCalledAtLoadTime(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sigil.yaml")

	content := `
networking:
  mode: "invalid-mode"
`
	err := os.WriteFile(cfgPath, []byte(content), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "networking.mode")
}

func TestValidate_MissingProvider(t *testing.T) {
	cfg := &config.Config{
		Models: config.ModelsConfig{
			Default: "anthropic/claude-sonnet-4-5",
		},
		Providers: map[string]config.ProviderConfig{},
	}

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

// validConfig returns a minimal config that passes all validation.
func validConfig() *config.Config {
	return &config.Config{
		Networking: config.NetworkingConfig{
			Mode:                     "local",
			Listen:                   "127.0.0.1:18789",
			ChatRateLimitEnabled:     true,
			ChatRateLimitRPM:         30,
			ChatRateLimitBurst:       10,
			ChatMaxConcurrentStreams: 5,
		},
		Providers: map[string]config.ProviderConfig{
			"anthropic": {APIKey: "test-key"},
		},
		Models: config.ModelsConfig{
			Default:  "anthropic/claude-sonnet-4-5",
			Failover: []string{"anthropic/claude-sonnet-4-5"},
			Budgets: config.BudgetsConfig{
				PerSessionTokens: 100000,
				PerHourUSD:       5.00,
				PerDayUSD:        50.00,
			},
		},
		Sessions: config.SessionsConfig{
			Memory: config.MemoryConfig{
				ActiveWindow: 20,
				Compaction: config.CompactionConfig{
					Strategy:     "summarize",
					SummaryModel: "anthropic/claude-haiku-4-5",
					BatchSize:    50,
				},
			},
		},
		Storage: config.StorageConfig{
			Backend: "sqlite",
		},
		Security: config.SecurityConfig{
			Scanner: config.ScannerConfig{
				Input:  "block",
				Tool:   "block",
				Output: "redact",
				Limits: config.ScannerLimitsConfig{
					MaxContentLength:        1048576,
					MaxPreNormContentLength: 5242880,
					MaxToolResultScanSize:   1048576,
					MaxToolContentScanSize:  524288,
				},
			},
		},
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	errs := cfg.Validate()
	assert.Empty(t, errs, "valid config should produce no validation errors")
}

func TestValidate_NetworkingMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"valid local", "local", false},
		{"valid tailscale", "tailscale", false},
		{"invalid mode", "kubernetes", true},
		{"empty mode", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.Mode = tt.mode
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "networking.mode")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "networking.mode")
				}
			}
		})
	}
}

func TestValidate_NetworkingListen(t *testing.T) {
	tests := []struct {
		name    string
		listen  string
		wantErr bool
	}{
		{"valid address", "127.0.0.1:8080", false},
		{"valid all interfaces", "0.0.0.0:9999", false},
		{"valid ipv6", "[::1]:8080", false},
		{"empty listen", "", true},
		{"missing port", "127.0.0.1", true},
		{"invalid port zero", "127.0.0.1:0", true},
		{"port too high", "127.0.0.1:70000", true},
		{"not a number", "127.0.0.1:abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.Listen = tt.listen
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "networking.listen")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "networking.listen")
				}
			}
		})
	}
}

func TestValidate_TrustedProxies(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		wantErr        bool
		errMsgContains string
	}{
		{
			name:           "empty list",
			trustedProxies: []string{},
			wantErr:        false,
		},
		{
			name:           "valid single CIDR",
			trustedProxies: []string{"10.0.0.0/8"},
			wantErr:        false,
		},
		{
			name:           "valid multiple CIDRs",
			trustedProxies: []string{"10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"},
			wantErr:        false,
		},
		{
			name:           "invalid CIDR string",
			trustedProxies: []string{"not-a-cidr"},
			wantErr:        true,
			errMsgContains: "networking.trusted_proxies",
		},
		{
			name:           "mixed valid and invalid entries",
			trustedProxies: []string{"10.0.0.0/8", "bad-cidr", "192.168.0.0/16"},
			wantErr:        true,
			errMsgContains: "networking.trusted_proxies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.TrustedProxies = tt.trustedProxies
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), tt.errMsgContains)
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "networking.trusted_proxies")
				}
			}
		})
	}
}

func TestValidate_DevCSPConnectSrc(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
		errMsg  string
	}{
		{"empty is valid", "", false, ""},
		{"valid http origin", "http://localhost:18789", false, ""},
		{"valid https origin", "https://dev.example.com:3000", false, ""},
		{"contains newline", "http://localhost:18789\nevil-header: injected", true, "must not contain CR, LF, or semicolons"},
		{"contains carriage return", "http://localhost:18789\revil", true, "must not contain CR, LF, or semicolons"},
		{"contains semicolon", "http://localhost:18789; script-src 'unsafe-eval'", true, "must not contain CR, LF, or semicolons"},
		{"missing scheme", "localhost:18789", true, "must be a valid URL origin"},
		{"missing host", "http://", true, "must be a valid URL origin"},
		{"bare path", "/some/path", true, "must be a valid URL origin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.DevCSPConnectSrc = tt.value
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), "dev_csp_connect_src") {
						found = true
						assert.Contains(t, err.Error(), tt.errMsg)
					}
				}
				assert.True(t, found, "expected error about dev_csp_connect_src")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "dev_csp_connect_src")
				}
			}
		})
	}
}

func TestValidate_StorageBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"valid sqlite", "sqlite", false},
		{"invalid backend", "postgres", true},
		{"empty backend", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Storage.Backend = tt.backend
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "storage.backend")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "storage.backend")
				}
			}
		})
	}
}

func TestValidate_ModelsDefault(t *testing.T) {
	tests := []struct {
		name    string
		model   string
		wantErr bool
	}{
		{"valid model", "anthropic/claude-sonnet-4-5", false},
		{"empty model", "", true},
		{"no slash", "plain-model", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Models.Default = tt.model
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), "models.default") {
						found = true
					}
				}
				assert.True(t, found, "expected error about models.default, got: %v", errs)
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "models.default")
				}
			}
		})
	}
}

func TestValidate_ModelProviderReference(t *testing.T) {
	t.Run("default model references missing provider", func(t *testing.T) {
		cfg := validConfig()
		cfg.Models.Default = "openai/gpt-4.1"
		// providers only has "anthropic", not "openai"
		errs := cfg.Validate()
		require.NotEmpty(t, errs)
		found := false
		for _, err := range errs {
			if strings.Contains(err.Error(), "provider") && strings.Contains(err.Error(), "openai") {
				found = true
			}
		}
		assert.True(t, found, "expected error about missing provider openai, got: %v", errs)
	})

	t.Run("failover model references missing provider", func(t *testing.T) {
		cfg := validConfig()
		cfg.Models.Failover = []string{"openai/gpt-4.1"}
		errs := cfg.Validate()
		require.NotEmpty(t, errs)
		found := false
		for _, err := range errs {
			if strings.Contains(err.Error(), "failover") && strings.Contains(err.Error(), "openai") {
				found = true
			}
		}
		assert.True(t, found, "expected error about failover referencing missing provider, got: %v", errs)
	})
}

func TestValidate_Budgets(t *testing.T) {
	tests := []struct {
		name             string
		perSessionTokens int
		perHourUSD       float64
		perDayUSD        float64
		wantErr          string
	}{
		{"valid budgets", 100000, 5.0, 50.0, ""},
		{"zero tokens", 0, 5.0, 50.0, "models.budgets.per_session_tokens"},
		{"negative tokens", -1, 5.0, 50.0, "models.budgets.per_session_tokens"},
		{"zero hour usd", 100000, 0, 50.0, "models.budgets.per_hour_usd"},
		{"negative hour usd", 100000, -1.0, 50.0, "models.budgets.per_hour_usd"},
		{"zero day usd", 100000, 5.0, 0, "models.budgets.per_day_usd"},
		{"negative day usd", 100000, 5.0, -5.0, "models.budgets.per_day_usd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Models.Budgets.PerSessionTokens = tt.perSessionTokens
			cfg.Models.Budgets.PerHourUSD = tt.perHourUSD
			cfg.Models.Budgets.PerDayUSD = tt.perDayUSD
			errs := cfg.Validate()
			if tt.wantErr != "" {
				require.NotEmpty(t, errs)
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), tt.wantErr) {
						found = true
					}
				}
				assert.True(t, found, "expected error about %s, got: %v", tt.wantErr, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidate_SessionMemory(t *testing.T) {
	tests := []struct {
		name         string
		activeWindow int
		wantErr      bool
	}{
		{"valid window", 20, false},
		{"minimum window", 1, false},
		{"zero window", 0, true},
		{"negative window", -5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Sessions.Memory.ActiveWindow = tt.activeWindow
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "sessions.memory.active_window")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "sessions.memory.active_window")
				}
			}
		})
	}
}

func TestValidate_CompactionStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		wantErr  bool
	}{
		{"valid summarize", "summarize", false},
		{"valid truncate", "truncate", false},
		{"invalid strategy", "random", true},
		{"empty strategy", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Sessions.Memory.Compaction.Strategy = tt.strategy
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "sessions.memory.compaction.strategy")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "sessions.memory.compaction.strategy")
				}
			}
		})
	}
}

func TestValidate_CompactionBatchSize(t *testing.T) {
	tests := []struct {
		name      string
		batchSize int
		wantErr   bool
	}{
		{"valid batch size", 50, false},
		{"minimum batch size", 1, false},
		{"zero batch size", 0, true},
		{"negative batch size", -10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Sessions.Memory.Compaction.BatchSize = tt.batchSize
			errs := cfg.Validate()
			if tt.wantErr {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0].Error(), "sessions.memory.compaction.batch_size")
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "sessions.memory.compaction.batch_size")
				}
			}
		})
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := &config.Config{
		Networking: config.NetworkingConfig{
			Mode:   "invalid",
			Listen: "",
		},
		Storage: config.StorageConfig{
			Backend: "postgres",
		},
		Models: config.ModelsConfig{
			Default: "",
			Budgets: config.BudgetsConfig{
				PerSessionTokens: -1,
				PerHourUSD:       -1,
				PerDayUSD:        -1,
			},
		},
		Sessions: config.SessionsConfig{
			Memory: config.MemoryConfig{
				ActiveWindow: 0,
				Compaction: config.CompactionConfig{
					Strategy:  "invalid",
					BatchSize: 0,
				},
			},
		},
	}

	errs := cfg.Validate()
	// Should collect multiple errors, not stop at the first one
	assert.GreaterOrEqual(t, len(errs), 5, "expected at least 5 validation errors, got %d: %v", len(errs), errs)
}

func TestLoad_InvalidConfigFailsFast(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sigil.yaml")

	content := `
networking:
  mode: "bogus"
  listen: "not-valid"
storage:
  backend: "mysql"
`
	err := os.WriteFile(cfgPath, []byte(content), 0o644)
	require.NoError(t, err)

	_, err = config.Load(cfgPath)
	require.Error(t, err, "Load should fail with invalid config")
	assert.Contains(t, err.Error(), "validating config")
}

func TestConfig_ScannerDefaults(t *testing.T) {
	v := viper.New()
	config.SetDefaults(v)

	assert.Equal(t, "block", v.GetString("security.scanner.input"))
	assert.Equal(t, "flag", v.GetString("security.scanner.tool"))
	assert.Equal(t, "redact", v.GetString("security.scanner.output"))
}

func TestConfig_ScannerValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		tool    string
		output  string
		wantErr bool
	}{
		{"valid defaults", "block", "block", "redact", false},
		{"all block", "block", "block", "block", false},
		{"invalid input mode", "invalid", "flag", "redact", true},
		{"invalid tool mode", "block", "nope", "redact", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			config.SetDefaults(v)
			v.Set("security.scanner.input", tt.input)
			v.Set("security.scanner.tool", tt.tool)
			v.Set("security.scanner.output", tt.output)

			cfg, err := config.FromViper(v)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, types.ScannerMode(tt.input), cfg.Security.Scanner.Input)
			}
		})
	}
}

func TestConfig_AllowPermissiveInputMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		allow   bool
		wantErr bool
	}{
		{"block mode does not require allow", "block", false, false},
		{"flag mode without allow is rejected", "flag", false, true},
		{"flag mode with allow is accepted", "flag", true, false},
		{"redact mode without allow is rejected", "redact", false, true},
		{"redact mode with allow is accepted", "redact", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			config.SetDefaults(v)
			v.Set("security.scanner.input", tt.input)
			v.Set("security.scanner.allow_permissive_input_mode", tt.allow)

			cfg, err := config.FromViper(v)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, types.ScannerMode(tt.input), cfg.Security.Scanner.Input)
			}
		})
	}
}

func TestConfig_AllowPermissiveInputModeEnvRejected(t *testing.T) {
	t.Setenv("SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE", "true")

	v := viper.New()
	config.SetDefaults(v)
	config.SetupEnv(v)

	_, err := config.FromViper(v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow_permissive_input_mode cannot be set via environment variable")
}

func TestConfig_ScannerModeEnvVarsRejected(t *testing.T) {
	tests := []struct {
		name        string
		envVar      string
		envVal      string
		wantErrFrag string
	}{
		{
			name:        "SIGIL_SECURITY_SCANNER_INPUT rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_INPUT",
			envVal:      "flag",
			wantErrFrag: "security.scanner.input cannot be set via environment variable",
		},
		{
			name:        "SIGIL_SECURITY_SCANNER_TOOL rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_TOOL",
			envVal:      "flag",
			wantErrFrag: "security.scanner.tool cannot be set via environment variable",
		},
		{
			name:        "SIGIL_SECURITY_SCANNER_OUTPUT rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_OUTPUT",
			envVal:      "flag",
			wantErrFrag: "security.scanner.output cannot be set via environment variable",
		},
		{
			name:        "SIGIL_SECURITY_SCANNER_DISABLE_ORIGIN_TAGGING rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_DISABLE_ORIGIN_TAGGING",
			envVal:      "true",
			wantErrFrag: "security.scanner.disable_origin_tagging cannot be set via environment variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envVal)

			v := viper.New()
			config.SetDefaults(v)
			config.SetupEnv(v)

			_, err := config.FromViper(v)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrFrag)
		})
	}
}

func TestConfig_ScannerLimitsDefaults(t *testing.T) {
	v := viper.New()
	config.SetDefaults(v)

	assert.Equal(t, 1048576, v.GetInt("security.scanner.limits.max_content_length"))
	assert.Equal(t, 5242880, v.GetInt("security.scanner.limits.max_pre_norm_content_length"))
	assert.Equal(t, 1048576, v.GetInt("security.scanner.limits.max_tool_result_scan_size"))
	assert.Equal(t, 524288, v.GetInt("security.scanner.limits.max_tool_content_scan_size"))
}

func TestConfig_ScannerLimitsValidation(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]int
		wantErr   string
	}{
		{
			name:    "defaults are valid",
			wantErr: "",
		},
		{
			name:      "max_content_length below minimum",
			overrides: map[string]int{"security.scanner.limits.max_content_length": 1000},
			wantErr:   "max_content_length must be >= 65536",
		},
		{
			name:      "max_content_length above maximum",
			overrides: map[string]int{"security.scanner.limits.max_content_length": 20_000_000},
			wantErr:   "max_content_length must be <= 10485760",
		},
		{
			name:      "max_pre_norm_content_length below minimum",
			overrides: map[string]int{"security.scanner.limits.max_pre_norm_content_length": 100},
			wantErr:   "max_pre_norm_content_length must be >= 65536",
		},
		{
			name:      "max_tool_result_scan_size below minimum",
			overrides: map[string]int{"security.scanner.limits.max_tool_result_scan_size": 0},
			wantErr:   "max_tool_result_scan_size must be >= 65536",
		},
		{
			name:      "max_tool_content_scan_size above maximum",
			overrides: map[string]int{"security.scanner.limits.max_tool_content_scan_size": 20_000_000},
			wantErr:   "max_tool_content_scan_size must be <= 10485760",
		},
		{
			name: "tool_content_scan_size must be less than content_length",
			overrides: map[string]int{
				"security.scanner.limits.max_content_length":         524288,
				"security.scanner.limits.max_tool_content_scan_size": 524288,
			},
			wantErr: "max_tool_content_scan_size (524288) must be < max_content_length (524288)",
		},
		{
			name: "tool_result_scan_size must be >= tool_content_scan_size",
			overrides: map[string]int{
				"security.scanner.limits.max_tool_result_scan_size":  100000,
				"security.scanner.limits.max_tool_content_scan_size": 200000,
			},
			wantErr: "max_tool_result_scan_size (100000) must be >= max_tool_content_scan_size (200000)",
		},
		{
			name: "valid custom limits",
			overrides: map[string]int{
				"security.scanner.limits.max_content_length":          2097152,
				"security.scanner.limits.max_pre_norm_content_length": 8388608,
				"security.scanner.limits.max_tool_result_scan_size":   2097152,
				"security.scanner.limits.max_tool_content_scan_size":  1048576,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			config.SetDefaults(v)
			for k, val := range tt.overrides {
				v.Set(k, val)
			}

			_, err := config.FromViper(v)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfig_ScannerLimitsEnvVarsRejected(t *testing.T) {
	tests := []struct {
		name        string
		envVar      string
		envVal      string
		wantErrFrag string
	}{
		{
			name:        "max_content_length env var rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_LIMITS_MAX_CONTENT_LENGTH",
			envVal:      "2097152",
			wantErrFrag: "max_content_length cannot be set via environment variable",
		},
		{
			name:        "max_pre_norm_content_length env var rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_LIMITS_MAX_PRE_NORM_CONTENT_LENGTH",
			envVal:      "8388608",
			wantErrFrag: "max_pre_norm_content_length cannot be set via environment variable",
		},
		{
			name:        "max_tool_result_scan_size env var rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_LIMITS_MAX_TOOL_RESULT_SCAN_SIZE",
			envVal:      "2097152",
			wantErrFrag: "max_tool_result_scan_size cannot be set via environment variable",
		},
		{
			name:        "max_tool_content_scan_size env var rejected",
			envVar:      "SIGIL_SECURITY_SCANNER_LIMITS_MAX_TOOL_CONTENT_SCAN_SIZE",
			envVal:      "524288",
			wantErrFrag: "max_tool_content_scan_size cannot be set via environment variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envVal)

			v := viper.New()
			config.SetDefaults(v)
			config.SetupEnv(v)

			_, err := config.FromViper(v)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrFrag)
		})
	}
}

func TestValidate_RateLimitConfig(t *testing.T) {
	tests := []struct {
		name    string
		rps     float64
		burst   int
		wantErr string
	}{
		{"disabled - zero rps and burst", 0, 0, ""},
		{"valid rate limit", 10.0, 20, ""},
		{"valid fractional rps", 0.5, 5, ""},
		{"negative rps", -5.0, 10, "rate_limit_rps must not be negative"},
		{"rps set but burst zero", 10.0, 0, "rate_limit_burst must be positive"},
		{"rps set but burst negative", 10.0, -5, "rate_limit_burst must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.RateLimitRPS = tt.rps
			cfg.Networking.RateLimitBurst = tt.burst
			errs := cfg.Validate()
			if tt.wantErr != "" {
				require.NotEmpty(t, errs)
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), tt.wantErr) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.wantErr, errs)
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "rate_limit")
				}
			}
		})
	}
}

func TestValidate_ChatRateLimitConfig(t *testing.T) {
	tests := []struct {
		name                 string
		enabled              bool
		rpm                  int
		burst                int
		maxConcurrentStreams int
		wantErr              string
	}{
		{
			name:                 "valid defaults",
			enabled:              true,
			rpm:                  30,
			burst:                10,
			maxConcurrentStreams: 5,
		},
		{
			name:                 "chat limiter disabled allows zero streams",
			enabled:              false,
			rpm:                  0,
			burst:                0,
			maxConcurrentStreams: 0,
		},
		{
			name:                 "chat limiter disabled allows negative streams",
			enabled:              false,
			rpm:                  0,
			burst:                0,
			maxConcurrentStreams: -1,
		},
		{
			name:                 "negative rpm",
			enabled:              true,
			rpm:                  -1,
			burst:                10,
			maxConcurrentStreams: 5,
			wantErr:              "chat_rate_limit_rpm must not be negative",
		},
		{
			name:                 "rpm set but burst is zero",
			enabled:              true,
			rpm:                  10,
			burst:                0,
			maxConcurrentStreams: 5,
			wantErr:              "chat_rate_limit_burst must be positive",
		},
		{
			name:                 "rpm set but burst is negative",
			enabled:              true,
			rpm:                  10,
			burst:                -1,
			maxConcurrentStreams: 5,
			wantErr:              "chat_rate_limit_burst must be positive",
		},
		{
			name:                 "enabled with zero max concurrent streams",
			enabled:              true,
			rpm:                  0,
			burst:                0,
			maxConcurrentStreams: 0,
			wantErr:              "chat_max_concurrent_streams must be positive",
		},
		{
			name:                 "enabled with negative max concurrent streams",
			enabled:              true,
			rpm:                  0,
			burst:                0,
			maxConcurrentStreams: -1,
			wantErr:              "chat_max_concurrent_streams must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Networking.ChatRateLimitEnabled = tt.enabled
			cfg.Networking.ChatRateLimitRPM = tt.rpm
			cfg.Networking.ChatRateLimitBurst = tt.burst
			cfg.Networking.ChatMaxConcurrentStreams = tt.maxConcurrentStreams

			errs := cfg.Validate()
			if tt.wantErr != "" {
				require.NotEmpty(t, errs)
				found := false
				for _, err := range errs {
					if strings.Contains(err.Error(), tt.wantErr) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.wantErr, errs)
			} else {
				for _, err := range errs {
					assert.NotContains(t, err.Error(), "chat_rate_limit")
					assert.NotContains(t, err.Error(), "chat_max_concurrent_streams")
				}
			}
		})
	}
}

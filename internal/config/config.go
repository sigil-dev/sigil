// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config

import (
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
	"github.com/spf13/viper"
)

// Config is the top-level Sigil configuration.
type Config struct {
	Networking NetworkingConfig           `mapstructure:"networking"`
	Auth       AuthConfig                 `mapstructure:"auth"`
	Providers  map[string]ProviderConfig  `mapstructure:"providers"`
	Models     ModelsConfig               `mapstructure:"models"`
	Sessions   SessionsConfig             `mapstructure:"sessions"`
	Storage    StorageConfig              `mapstructure:"storage"`
	Workspaces map[string]WorkspaceConfig `mapstructure:"workspaces"`
	Security   SecurityConfig             `mapstructure:"security"`
}

// AuthConfig controls REST API authentication.
type AuthConfig struct {
	Tokens []TokenConfig `mapstructure:"tokens"`
}

// TokenConfig maps a bearer token to a user identity.
type TokenConfig struct {
	Token       string   `mapstructure:"token"`
	UserID      string   `mapstructure:"user_id"`
	Name        string   `mapstructure:"name"`
	Permissions []string `mapstructure:"permissions"`
}

// NetworkingConfig controls how Sigil listens for connections.
type NetworkingConfig struct {
	Mode           string   `mapstructure:"mode"`
	Listen         string   `mapstructure:"listen"`
	CORSOrigins    []string `mapstructure:"cors_origins"`
	EnableHSTS     bool     `mapstructure:"enable_hsts"`
	RateLimitRPS   float64  `mapstructure:"rate_limit_rps"`
	RateLimitBurst int      `mapstructure:"rate_limit_burst"`
	TrustedProxies []string `mapstructure:"trusted_proxies"` // CIDR ranges of trusted reverse proxies
}

// ProviderConfig holds credentials and endpoint for an LLM provider.
type ProviderConfig struct {
	APIKey   string `mapstructure:"api_key"`
	Endpoint string `mapstructure:"endpoint"`
}

// ModelsConfig controls model selection and budgets.
type ModelsConfig struct {
	Default  string        `mapstructure:"default"`
	Failover []string      `mapstructure:"failover"`
	Budgets  BudgetsConfig `mapstructure:"budgets"`
}

// BudgetsConfig sets token and cost limits.
type BudgetsConfig struct {
	PerSessionTokens int     `mapstructure:"per_session_tokens"`
	PerHourUSD       float64 `mapstructure:"per_hour_usd"`
	PerDayUSD        float64 `mapstructure:"per_day_usd"`
}

// SessionsConfig controls session behavior.
type SessionsConfig struct {
	Memory MemoryConfig `mapstructure:"memory"`
}

// MemoryConfig controls the agent memory window and compaction.
type MemoryConfig struct {
	ActiveWindow int              `mapstructure:"active_window"`
	Compaction   CompactionConfig `mapstructure:"compaction"`
}

// CompactionConfig controls how conversation history is compacted.
type CompactionConfig struct {
	Strategy     string `mapstructure:"strategy"`
	SummaryModel string `mapstructure:"summary_model"`
	BatchSize    int    `mapstructure:"batch_size"`
}

// StorageConfig selects the storage backend.
type StorageConfig struct {
	Backend string `mapstructure:"backend"`
}

// WorkspaceConfig defines a single workspace.
type WorkspaceConfig struct {
	Description string          `mapstructure:"description"`
	Members     []string        `mapstructure:"members"`
	Bindings    []BindingConfig `mapstructure:"bindings"`
	Tools       ToolsConfig     `mapstructure:"tools"`
	Skills      []string        `mapstructure:"skills"`
}

// BindingConfig maps a channel type and ID to a workspace.
type BindingConfig struct {
	Channel   string `mapstructure:"channel"`
	ChannelID string `mapstructure:"channel_id"`
}

// ToolsConfig controls which tools are available in a workspace.
type ToolsConfig struct {
	Allow []string `mapstructure:"allow"`
	Deny  []string `mapstructure:"deny"`
}

// SecurityConfig holds security subsystem settings.
type SecurityConfig struct {
	Scanner ScannerConfig `mapstructure:"scanner"`
}

// ScannerConfig controls per-hook scanner detection modes.
type ScannerConfig struct {
	Input                    types.ScannerMode `mapstructure:"input"`
	Tool                     types.ScannerMode `mapstructure:"tool"`
	Output                   types.ScannerMode `mapstructure:"output"`
	AllowPermissiveInputMode bool              `mapstructure:"allow_permissive_input_mode"`
	// DisableOriginTagging controls whether origin tag prepending is disabled.
	// When false (the default), origin tags ([user_input], [tool_output], etc.)
	// are prepended to message content when sending to LLM providers.
	// Set to true to disable tagging (reduces upstream token count and avoids
	// altering message content sent to providers).
	//
	// The zero value (false) is the safe default: tagging enabled.
	DisableOriginTagging bool `mapstructure:"disable_origin_tagging"`
}

// SetDefaults applies Sigil's default configuration values to v.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("networking.mode", "local")
	v.SetDefault("networking.listen", "127.0.0.1:18789")
	v.SetDefault("storage.backend", "sqlite")
	v.SetDefault("sessions.memory.active_window", 20)
	v.SetDefault("sessions.memory.compaction.strategy", "summarize")
	v.SetDefault("sessions.memory.compaction.summary_model", "anthropic/claude-haiku-4-5")
	v.SetDefault("sessions.memory.compaction.batch_size", 50)
	v.SetDefault("models.default", "anthropic/claude-sonnet-4-5")
	v.SetDefault("models.budgets.per_session_tokens", 100000)
	v.SetDefault("models.budgets.per_hour_usd", 5.00)
	v.SetDefault("models.budgets.per_day_usd", 50.00)
	v.SetDefault("security.scanner.input", "block")
	v.SetDefault("security.scanner.tool", "flag")
	v.SetDefault("security.scanner.output", "redact")
	v.SetDefault("security.scanner.allow_permissive_input_mode", false)
	v.SetDefault("security.scanner.disable_origin_tagging", false)
}

// SetupEnv configures environment variable binding on v with prefix SIGIL_.
func SetupEnv(v *viper.Viper) {
	v.SetEnvPrefix("SIGIL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}

// FromViper unmarshals and validates a Config from an already-configured
// Viper instance. Use this when flags and env vars are bound to v externally
// (e.g. from Cobra CLI flag bindings).
func FromViper(v *viper.Viper) (*Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeConfigParseInvalidFormat, "unmarshalling config: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "validating config: %w", errors.Join(errs...))
	}

	return &cfg, nil
}

// Load reads configuration from the given path (or defaults) with
// environment variable overrides (prefix SIGIL_).
// For CLI usage where flags are bound to a shared Viper, prefer FromViper.
func Load(path string) (*Config, error) {
	return LoadWithSecrets(path, nil)
}

// LoadWithSecrets reads configuration and resolves any keyring:// URI values
// using the provided secret store. If store is nil, a default KeyringStore is
// used. Pass a nil store to use the OS keyring, or provide a custom Store
// implementation for testing.
func LoadWithSecrets(path string, store secrets.Store) (*Config, error) {
	v := viper.New()

	SetDefaults(v)
	SetupEnv(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "reading config %s: %w", path, err)
		}
	}

	if store == nil {
		store = secrets.NewKeyringStore()
	}
	secrets.ResolveViperSecrets(v, store)

	return FromViper(v)
}

// Validate checks the configuration for logical errors.
// It returns a slice of all validation errors found, collecting all issues
// rather than stopping at the first one.
func (c *Config) Validate() []error {
	var errs []error

	errs = append(errs, c.validateNetworking()...)
	errs = append(errs, c.validateStorage()...)
	errs = append(errs, c.validateModels()...)
	errs = append(errs, c.validateSessions()...)
	errs = append(errs, c.validateSecurity()...)

	return errs
}

func (c *Config) validateNetworking() []error {
	var errs []error

	validModes := map[string]bool{"local": true, "tailscale": true}
	if err := validateStringInSet(c.Networking.Mode, "networking.mode", validModes); err != nil {
		errs = append(errs, err)
	}

	if c.Networking.Listen == "" {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "config: networking.listen must not be empty"))
	} else {
		host, portStr, err := net.SplitHostPort(c.Networking.Listen)
		if err != nil {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: networking.listen must be a valid host:port address, got %q: %w",
				c.Networking.Listen, err,
			))
		} else {
			_ = host // host can be empty (e.g., ":8080"), which is valid
			port, err := strconv.Atoi(portStr)
			if err != nil {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
					"config: networking.listen port must be a number, got %q",
					portStr,
				))
			} else if port < 1 || port > 65535 {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
					"config: networking.listen port must be between 1 and 65535, got %d",
					port,
				))
			}
		}
	}

	if c.Networking.RateLimitRPS < 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: networking.rate_limit_rps must not be negative, got %g",
			c.Networking.RateLimitRPS,
		))
	}

	if c.Networking.RateLimitRPS > 0 && c.Networking.RateLimitBurst <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: networking.rate_limit_burst must be positive when rate_limit_rps is set, got burst=%d, rps=%g",
			c.Networking.RateLimitBurst, c.Networking.RateLimitRPS,
		))
	}

	// Validate trusted proxy CIDRs if provided
	for i, cidr := range c.Networking.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: networking.trusted_proxies[%d] is not a valid CIDR range, got %q: %v",
				i, cidr, err,
			))
		}
	}

	return errs
}

func (c *Config) validateStorage() []error {
	var errs []error

	validBackends := map[string]bool{"sqlite": true}
	if err := validateStringInSet(c.Storage.Backend, "storage.backend", validBackends); err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (c *Config) validateModels() []error {
	var errs []error

	if c.Models.Default == "" {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "config: models.default must not be empty"))
	} else if !strings.Contains(c.Models.Default, "/") {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: models.default must be in \"provider/model\" format, got %q",
			c.Models.Default,
		))
	} else if c.Providers != nil {
		// Only cross-reference providers when the providers section exists
		// in config. A nil map means no providers section was configured
		// (e.g., defaults only on fresh install), which is valid.
		providerName := providerFromModel(c.Models.Default)
		if _, ok := c.Providers[providerName]; !ok {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: models.default %q references provider %q which is not configured",
				c.Models.Default, providerName,
			))
		}
	}

	for i, model := range c.Models.Failover {
		if !strings.Contains(model, "/") {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: models.failover[%d] must be in \"provider/model\" format, got %q",
				i, model,
			))
			continue
		}
		if c.Providers != nil {
			providerName := providerFromModel(model)
			if _, ok := c.Providers[providerName]; !ok {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
					"config: models.failover[%d] %q references provider %q which is not configured",
					i, model, providerName,
				))
			}
		}
	}

	if c.Models.Budgets.PerSessionTokens <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: models.budgets.per_session_tokens must be greater than 0, got %d",
			c.Models.Budgets.PerSessionTokens,
		))
	}

	if c.Models.Budgets.PerHourUSD <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: models.budgets.per_hour_usd must be greater than 0, got %g",
			c.Models.Budgets.PerHourUSD,
		))
	}

	if c.Models.Budgets.PerDayUSD <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: models.budgets.per_day_usd must be greater than 0, got %g",
			c.Models.Budgets.PerDayUSD,
		))
	}

	return errs
}

func (c *Config) validateSessions() []error {
	var errs []error

	if c.Sessions.Memory.ActiveWindow <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: sessions.memory.active_window must be greater than 0, got %d",
			c.Sessions.Memory.ActiveWindow,
		))
	}

	validStrategies := map[string]bool{"summarize": true, "truncate": true}
	if err := validateStringInSet(c.Sessions.Memory.Compaction.Strategy, "sessions.memory.compaction.strategy", validStrategies); err != nil {
		errs = append(errs, err)
	}

	if c.Sessions.Memory.Compaction.BatchSize <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: sessions.memory.compaction.batch_size must be greater than 0, got %d",
			c.Sessions.Memory.Compaction.BatchSize,
		))
	}

	return errs
}

func (c *Config) validateSecurity() []error {
	var errs []error

	// Validate scanner modes using types.ScannerMode.Valid(), which is the
	// authoritative check in pkg/types. This avoids duplicating the valid-mode set here.
	for _, pair := range []struct {
		field string
		value types.ScannerMode
	}{
		{"security.scanner.input", c.Security.Scanner.Input},
		{"security.scanner.tool", c.Security.Scanner.Tool},
		{"security.scanner.output", c.Security.Scanner.Output},
	} {
		if pair.value == "" {
			continue // empty means "use default" — matches NewScannerModesFromConfig behavior
		}
		if !pair.value.Valid() {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: %s: invalid scanner mode %q", pair.field, pair.value))
		}
	}

	// Require explicit opt-in to use non-block modes for input scanning.
	// Only check permissive-mode policy when the input mode is valid; invalid
	// modes already produce an error above and would otherwise generate a
	// second, misleading error here.
	if c.Security.Scanner.Input.Valid() && c.Security.Scanner.Input != types.ScannerModeBlock && !c.Security.Scanner.AllowPermissiveInputMode {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: security.scanner.input is %q but only 'block' is allowed without security.scanner.allow_permissive_input_mode=true",
			c.Security.Scanner.Input,
		))
	}

	// Scanner mode env vars are rejected at validate-time to prevent environment
	// variable injection from weakening security scanning in production. Environment
	// variables are less auditable than config files (they can be injected by
	// container orchestrators, CI systems, or shell profiles without appearing in
	// version-controlled config). All scanner mode fields must be set in the config
	// file or mounted secrets. Container deployments should use mounted config files
	// or secret volumes rather than env vars for scanner settings.
	//
	// Note on Viper binding timing: os.Getenv runs at validate-time (after Viper
	// has already called AutomaticEnv() and may have merged env values into the
	// unmarshalled struct). This check detects env var presence and rejects the
	// startup, but it does NOT retroactively prevent Viper from reading the env
	// var into cfg — it surfaces the violation as a fatal startup error so the
	// operator is forced to remove the env var rather than silently proceeding
	// with a potentially weakened scanner configuration.
	blockedScannerEnvVars := []struct {
		envVar string
		field  string
	}{
		{"SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE", "security.scanner.allow_permissive_input_mode"},
		{"SIGIL_SECURITY_SCANNER_INPUT", "security.scanner.input"},
		{"SIGIL_SECURITY_SCANNER_TOOL", "security.scanner.tool"},
		{"SIGIL_SECURITY_SCANNER_OUTPUT", "security.scanner.output"},
		{"SIGIL_SECURITY_SCANNER_DISABLE_ORIGIN_TAGGING", "security.scanner.disable_origin_tagging"},
	}
	for _, blocked := range blockedScannerEnvVars {
		if os.Getenv(blocked.envVar) != "" {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
				"config: %s cannot be set via environment variable", blocked.field))
		}
	}

	return errs
}

// providerFromModel extracts the provider prefix from a "provider/model" string.
func providerFromModel(model string) string {
	if idx := strings.Index(model, "/"); idx > 0 {
		return model[:idx]
	}
	return model
}

// validateStringInSet checks if a value is in a set of valid options.
// Returns an error with the given field name if the value is not valid.
func validateStringInSet(value, fieldName string, validSet map[string]bool) error {
	if !validSet[value] {
		validOptions := make([]string, 0, len(validSet))
		for k := range validSet {
			validOptions = append(validOptions, k)
		}
		sort.Strings(validOptions)
		return sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: %s must be one of %v, got %q",
			fieldName, validOptions, value)
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config

import (
	"errors"
	"net"
	"strconv"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/viper"
)

// Config is the top-level Sigil configuration.
type Config struct {
	Networking NetworkingConfig           `mapstructure:"networking"`
	Providers  map[string]ProviderConfig  `mapstructure:"providers"`
	Models     ModelsConfig               `mapstructure:"models"`
	Sessions   SessionsConfig             `mapstructure:"sessions"`
	Storage    StorageConfig              `mapstructure:"storage"`
	Workspaces map[string]WorkspaceConfig `mapstructure:"workspaces"`
}

// NetworkingConfig controls how Sigil listens for connections.
type NetworkingConfig struct {
	Mode   string `mapstructure:"mode"`
	Listen string `mapstructure:"listen"`
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
	Description string      `mapstructure:"description"`
	Members     []string    `mapstructure:"members"`
	Tools       ToolsConfig `mapstructure:"tools"`
	Skills      []string    `mapstructure:"skills"`
}

// ToolsConfig controls which tools are available in a workspace.
type ToolsConfig struct {
	Allow []string `mapstructure:"allow"`
}

// Load reads configuration from the given path (or defaults) with
// environment variable overrides (prefix SIGIL_).
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("networking.mode", "local")
	v.SetDefault("networking.listen", "127.0.0.1:18789")
	v.SetDefault("storage.backend", "sqlite")
	v.SetDefault("sessions.memory.active_window", 20)
	v.SetDefault("sessions.memory.compaction.strategy", "summarize")
	v.SetDefault("sessions.memory.compaction.summary_model", "anthropic/claude-haiku-4-5")
	v.SetDefault("sessions.memory.compaction.batch_size", 50)
	v.SetDefault("models.default", "anthropic/claude-sonnet-4-5")
	v.SetDefault("models.budgets.per_session_tokens", 100000)
	v.SetDefault("models.budgets.per_day_usd", 50.00)

	// Environment
	v.SetEnvPrefix("SIGIL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// File
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "reading config %s: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "unmarshalling config: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "validating config: %w", errors.Join(errs...))
	}

	return &cfg, nil
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

	return errs
}

func (c *Config) validateNetworking() []error {
	var errs []error

	validModes := map[string]bool{"local": true, "tailscale": true}
	if !validModes[c.Networking.Mode] {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: networking.mode must be one of [local, tailscale], got %q",
			c.Networking.Mode,
		))
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

	return errs
}

func (c *Config) validateStorage() []error {
	var errs []error

	validBackends := map[string]bool{"sqlite": true}
	if !validBackends[c.Storage.Backend] {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: storage.backend must be one of [sqlite], got %q",
			c.Storage.Backend,
		))
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
	if !validStrategies[c.Sessions.Memory.Compaction.Strategy] {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: sessions.memory.compaction.strategy must be one of [summarize, truncate], got %q",
			c.Sessions.Memory.Compaction.Strategy,
		))
	}

	if c.Sessions.Memory.Compaction.BatchSize <= 0 {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"config: sessions.memory.compaction.batch_size must be greater than 0, got %d",
			c.Sessions.Memory.Compaction.BatchSize,
		))
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

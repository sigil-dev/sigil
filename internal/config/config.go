// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level Sigil configuration.
type Config struct {
	Networking NetworkingConfig            `mapstructure:"networking"`
	Providers  map[string]ProviderConfig   `mapstructure:"providers"`
	Models     ModelsConfig                `mapstructure:"models"`
	Sessions   SessionsConfig              `mapstructure:"sessions"`
	Storage    StorageConfig               `mapstructure:"storage"`
	Workspaces map[string]WorkspaceConfig  `mapstructure:"workspaces"`
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
			return nil, fmt.Errorf("reading config %s: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	return &cfg, nil
}

// Validate checks the configuration for logical errors.
// It returns a slice of all validation errors found.
func (c *Config) Validate() []error {
	var errs []error

	if c.Models.Default != "" {
		providerName := providerFromModel(c.Models.Default)
		if _, ok := c.Providers[providerName]; !ok {
			errs = append(errs, fmt.Errorf(
				"default model %q references provider %q which is not configured",
				c.Models.Default, providerName,
			))
		}
	}

	for i, model := range c.Models.Failover {
		providerName := providerFromModel(model)
		if _, ok := c.Providers[providerName]; !ok {
			errs = append(errs, fmt.Errorf(
				"failover model [%d] %q references provider %q which is not configured",
				i, model, providerName,
			))
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

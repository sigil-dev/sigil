// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package plugin provides public types for plugin authors.
// These types define the plugin manifest structure and execution configuration.
package plugin

// PluginType identifies the category of plugin.
type PluginType string

const (
	PluginTypeProvider PluginType = "provider"
	PluginTypeChannel  PluginType = "channel"
	PluginTypeTool     PluginType = "tool"
	PluginTypeSkill    PluginType = "skill"
)

// ExecutionTier determines the isolation level for a plugin.
type ExecutionTier string

const (
	ExecutionTierWasm      ExecutionTier = "wasm"
	ExecutionTierProcess   ExecutionTier = "process"
	ExecutionTierContainer ExecutionTier = "container"
)

// Manifest describes a plugin's metadata, capabilities, and execution requirements.
// This is loaded from plugin.yaml in the plugin directory.
type Manifest struct {
	Name             string                 `yaml:"name"`
	Version          string                 `yaml:"version"`
	Type             PluginType             `yaml:"type"`
	Engine           string                 `yaml:"engine"`
	License          string                 `yaml:"license,omitempty"`
	Capabilities     []Capability           `yaml:"capabilities"`
	DenyCapabilities []Capability           `yaml:"deny_capabilities,omitempty"`
	Execution        ExecutionConfig        `yaml:"execution"`
	ConfigSchema     map[string]interface{} `yaml:"config_schema,omitempty"`
	Dependencies     map[string]string      `yaml:"dependencies,omitempty"`
	Lifecycle        LifecycleConfig        `yaml:"lifecycle,omitempty"`
	Storage          StorageConfig          `yaml:"storage,omitempty"`
}

// Capability represents a permission pattern.
type Capability struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description,omitempty"`
}

// ExecutionConfig defines how the plugin should be executed.
type ExecutionConfig struct {
	Tier    ExecutionTier `yaml:"tier"`
	Sandbox SandboxConfig `yaml:"sandbox,omitempty"`
	Image   string        `yaml:"image,omitempty"`
	Network string        `yaml:"network,omitempty"`
	Memory  string        `yaml:"memory_limit,omitempty"`
}

// SandboxConfig defines sandbox restrictions for process-tier plugins.
type SandboxConfig struct {
	Filesystem FilesystemConfig `yaml:"filesystem,omitempty"`
	Network    NetworkConfig    `yaml:"network,omitempty"`
}

// FilesystemConfig defines filesystem access rules.
type FilesystemConfig struct {
	WriteAllow []string `yaml:"write_allow,omitempty"`
	ReadDeny   []string `yaml:"read_deny,omitempty"`
}

// NetworkConfig defines network access rules.
type NetworkConfig struct {
	Allow []string `yaml:"allow,omitempty"`
	Proxy bool     `yaml:"proxy,omitempty"`
}

// LifecycleConfig defines plugin lifecycle behavior.
type LifecycleConfig struct {
	HotReload               bool   `yaml:"hot_reload,omitempty"`
	GracefulShutdownTimeout string `yaml:"graceful_shutdown_timeout,omitempty"`
}

// StorageConfig defines plugin storage requirements.
type StorageConfig struct {
	KV      bool           `yaml:"kv,omitempty"`
	Volumes []VolumeConfig `yaml:"volumes,omitempty"`
	Memory  MemoryConfig   `yaml:"memory,omitempty"`
}

// VolumeConfig defines a persistent volume for a plugin.
type VolumeConfig struct {
	Name      string `yaml:"name"`
	Mount     string `yaml:"mount"`
	SizeLimit string `yaml:"size_limit,omitempty"`
	Persist   bool   `yaml:"persist,omitempty"`
}

// MemoryConfig defines memory storage collections.
type MemoryConfig struct {
	Collections []CollectionConfig `yaml:"collections,omitempty"`
}

// CollectionConfig defines a memory collection.
type CollectionConfig struct {
	Name           string `yaml:"name"`
	EmbeddingModel string `yaml:"embedding_model,omitempty"`
	MaxEntries     int    `yaml:"max_entries,omitempty"`
}

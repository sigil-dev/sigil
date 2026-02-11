// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"fmt"
	"regexp"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"gopkg.in/yaml.v3"
)

// PluginType identifies the category of plugin (internal runtime representation).
type PluginType string

const (
	TypeProvider PluginType = "provider"
	TypeChannel  PluginType = "channel"
	TypeTool     PluginType = "tool"
	TypeSkill    PluginType = "skill"
)

// validPluginTypes enumerates recognized plugin types.
var validPluginTypes = map[PluginType]bool{
	TypeProvider: true,
	TypeChannel:  true,
	TypeTool:     true,
	TypeSkill:    true,
}

// ExecutionTier determines the isolation level for a plugin (internal runtime representation).
type ExecutionTier string

const (
	TierWasm      ExecutionTier = "wasm"
	TierProcess   ExecutionTier = "process"
	TierContainer ExecutionTier = "container"
)

// validExecutionTiers enumerates recognized execution tiers.
var validExecutionTiers = map[ExecutionTier]bool{
	TierWasm:      true,
	TierProcess:   true,
	TierContainer: true,
}

// capPatternRe matches valid capability pattern characters.
var capPatternRe = regexp.MustCompile(`^[a-zA-Z0-9.*_\-/]+$`)

// semverRe matches strict semver (no "v" prefix): MAJOR.MINOR.PATCH[-prerelease][+build].
// Leading zeros on numeric segments are disallowed per semver spec.
// Matches the same pattern as pkg/plugin/validate.go.
var semverRe = regexp.MustCompile(
	`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)` +
		`(?:-(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?` +
		`(?:\+(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`,
)

// Manifest is the runtime's internal parsed representation of a plugin manifest.
// It uses simplified types (e.g., Capabilities []string) optimized for runtime
// enforcement checks. This is distinct from the public SDK Manifest in pkg/plugin.
type Manifest struct {
	Name             string          `yaml:"name"`
	Version          string          `yaml:"version"`
	Type             PluginType      `yaml:"type"`
	Engine           string          `yaml:"engine,omitempty"`
	License          string          `yaml:"license,omitempty"`
	Capabilities     []string        `yaml:"capabilities"`
	DenyCapabilities []string        `yaml:"deny_capabilities,omitempty"`
	Execution        ExecutionConfig `yaml:"execution"`
	Lifecycle        LifecycleConfig `yaml:"lifecycle,omitempty"`
}

// ExecutionConfig defines how the plugin should be executed.
type ExecutionConfig struct {
	Tier    ExecutionTier `yaml:"tier"`
	Sandbox SandboxConfig `yaml:"sandbox,omitempty"`
}

// SandboxConfig defines sandbox restrictions for process-tier plugins.
type SandboxConfig struct {
	Filesystem FilesystemSandbox `yaml:"filesystem,omitempty"`
	Network    NetworkSandbox    `yaml:"network,omitempty"`
}

// FilesystemSandbox defines filesystem access rules for sandboxed plugins.
type FilesystemSandbox struct {
	WriteAllow []string `yaml:"write_allow,omitempty"`
	ReadDeny   []string `yaml:"read_deny,omitempty"`
}

// NetworkSandbox defines network access rules for sandboxed plugins.
type NetworkSandbox struct {
	Allow []string `yaml:"allow,omitempty"`
	Proxy bool     `yaml:"proxy,omitempty"`
}

// LifecycleConfig defines plugin lifecycle behavior.
type LifecycleConfig struct {
	HotReload               bool   `yaml:"hot_reload,omitempty"`
	GracefulShutdownTimeout string `yaml:"graceful_shutdown_timeout,omitempty"`
}

// ParseManifest parses YAML data into a Manifest and validates it.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest parse: %s", err)
	}

	if errs := m.Validate(); len(errs) > 0 {
		// Return the first validation error for simplicity.
		return nil, errs[0]
	}

	return &m, nil
}

// Validate checks that the Manifest is well-formed. It returns all validation
// errors found rather than stopping at the first one.
func (m *Manifest) Validate() []error {
	var errs []error

	if strings.TrimSpace(m.Name) == "" {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest validation: name must not be empty"))
	}

	if strings.TrimSpace(m.Version) == "" {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest validation: version must not be empty"))
	} else if !semverRe.MatchString(m.Version) {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest validation: version must be valid semver (MAJOR.MINOR.PATCH), got %q", m.Version))
	}

	if !validPluginTypes[m.Type] {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest validation: type must be one of [provider, channel, tool, skill], got %q", m.Type))
	}

	if !validExecutionTiers[m.Execution.Tier] {
		errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"manifest validation: execution tier must be one of [wasm, process, container], got %q", m.Execution.Tier))
	}

	for i, cap := range m.Capabilities {
		if err := validateCapPattern(cap); err != nil {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
				"manifest validation: capabilities[%d]: %s", i, err))
		}
	}

	for i, dc := range m.DenyCapabilities {
		if err := validateCapPattern(dc); err != nil {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
				"manifest validation: deny_capabilities[%d]: %s", i, err))
		}
	}

	// Check for grant/deny conflicts.
	for _, dc := range m.DenyCapabilities {
		for _, grant := range m.Capabilities {
			if capabilitiesConflict(grant, dc) {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
					"manifest validation: deny pattern %q conflicts with granted capability %q",
					dc, grant))
			}
		}
	}

	return errs
}

// validateCapPattern checks that a capability pattern string is well-formed.
// This catches malformed patterns at manifest load time so that
// security.MatchCapability never returns errors during enforcement.
func validateCapPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("capability pattern must not be empty")
	}
	if !capPatternRe.MatchString(pattern) {
		return fmt.Errorf("capability pattern %q contains invalid characters", pattern)
	}
	if strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") {
		return fmt.Errorf("capability pattern %q must not start or end with a dot", pattern)
	}
	if strings.Contains(pattern, "..") {
		return fmt.Errorf("capability pattern %q contains consecutive dots", pattern)
	}
	// Reject patterns that would exceed the segment limit enforced by
	// security.MatchCapability (maxSegments = 32). Catching this at
	// validation time prevents silent skip in CapabilitySet.Contains.
	if segments := strings.Count(pattern, ".") + 1; segments > 32 {
		return fmt.Errorf("capability pattern %q exceeds maximum 32 segments (has %d)", pattern, segments)
	}
	return nil
}

// capabilitiesConflict returns true if a grant and deny pattern overlap.
func capabilitiesConflict(grant, deny string) bool {
	if grant == deny {
		return true
	}

	grantParts := strings.Split(grant, ".")
	denyParts := strings.Split(deny, ".")

	return segmentsConflict(grantParts, denyParts)
}

// segmentsConflict checks whether two dot-split capability patterns overlap.
func segmentsConflict(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == "*" || b[i] == "*" {
			return true
		}
		if a[i] != b[i] {
			return false
		}
	}
	return len(a) == len(b)
}

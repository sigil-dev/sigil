// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"fmt"
	"regexp"
	"strings"
)

// semverRe matches strict semver (no "v" prefix): MAJOR.MINOR.PATCH[-prerelease][+build].
// Leading zeros on numeric segments are disallowed per semver spec.
var semverRe = regexp.MustCompile(
	`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)` +
		`(?:-(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?` +
		`(?:\+(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`,
)

// capPatternRe matches valid capability pattern characters:
// alphanumeric, dots, asterisks, underscores, hyphens, and forward slashes.
var capPatternRe = regexp.MustCompile(`^[a-zA-Z0-9.*_\-/]+$`)

// validPluginTypes enumerates recognized plugin types.
var validPluginTypes = map[PluginType]bool{
	PluginTypeProvider: true,
	PluginTypeChannel:  true,
	PluginTypeTool:     true,
	PluginTypeSkill:    true,
}

// validExecutionTiers enumerates recognized execution tiers.
var validExecutionTiers = map[ExecutionTier]bool{
	ExecutionTierWasm:      true,
	ExecutionTierProcess:   true,
	ExecutionTierContainer: true,
}

// Validate checks that the Manifest is well-formed according to Sigil's security model.
// It returns an error describing the first validation failure encountered, or nil
// if the manifest is valid.
func (m *Manifest) Validate() error {
	if err := m.validateName(); err != nil {
		return err
	}
	if err := m.validateVersion(); err != nil {
		return err
	}
	if err := m.validateType(); err != nil {
		return err
	}
	if err := m.validateCapabilities(); err != nil {
		return err
	}
	if err := m.validateExecution(); err != nil {
		return err
	}
	if err := m.validateDenyCapabilities(); err != nil {
		return err
	}
	return nil
}

func (m *Manifest) validateName() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("manifest validation: name must not be empty")
	}
	return nil
}

func (m *Manifest) validateVersion() error {
	if m.Version == "" {
		return fmt.Errorf("manifest validation: version must not be empty")
	}
	if !semverRe.MatchString(m.Version) {
		return fmt.Errorf("manifest validation: version must be valid semver (MAJOR.MINOR.PATCH), got %q", m.Version)
	}
	return nil
}

func (m *Manifest) validateType() error {
	if !validPluginTypes[m.Type] {
		return fmt.Errorf("manifest validation: type must be one of [provider, channel, tool, skill], got %q", m.Type)
	}
	return nil
}

func (m *Manifest) validateCapabilities() error {
	for i, cap := range m.Capabilities {
		if err := validateCapabilityPattern(cap.Pattern); err != nil {
			return fmt.Errorf("manifest validation: capabilities[%d]: %w", i, err)
		}
	}
	return nil
}

func (m *Manifest) validateExecution() error {
	if !validExecutionTiers[m.Execution.Tier] {
		return fmt.Errorf("manifest validation: execution tier must be one of [wasm, process, container], got %q", m.Execution.Tier)
	}
	return nil
}

func (m *Manifest) validateDenyCapabilities() error {
	for i, dc := range m.DenyCapabilities {
		if err := validateDenyCapabilityPattern(dc.Pattern); err != nil {
			return fmt.Errorf("manifest validation: deny_capabilities[%d]: %w", i, err)
		}
		if err := m.checkDenyConflict(dc); err != nil {
			return fmt.Errorf("manifest validation: deny_capabilities[%d]: %w", i, err)
		}
	}
	return nil
}

// validateCapabilityPattern checks that a single capability pattern string is well-formed.
func validateCapabilityPattern(pattern string) error {
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
	return nil
}

// validateDenyCapabilityPattern checks a deny capability pattern string.
func validateDenyCapabilityPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("deny capability pattern must not be empty")
	}
	if !capPatternRe.MatchString(pattern) {
		return fmt.Errorf("deny capability pattern %q contains invalid characters", pattern)
	}
	if strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") {
		return fmt.Errorf("deny capability pattern %q must not start or end with a dot", pattern)
	}
	if strings.Contains(pattern, "..") {
		return fmt.Errorf("deny capability pattern %q contains consecutive dots", pattern)
	}
	return nil
}

// checkDenyConflict detects if a deny capability conflicts with any granted capability.
// A conflict exists when a deny pattern and a granted pattern overlap:
//   - exact match (both are identical)
//   - deny glob covers a granted pattern (deny "exec.*" vs grant "exec.run")
//   - granted glob covers a denied pattern (grant "exec.*" vs deny "exec.run")
func (m *Manifest) checkDenyConflict(deny Capability) error {
	for _, grant := range m.Capabilities {
		if capabilitiesConflict(grant.Pattern, deny.Pattern) {
			return fmt.Errorf(
				"deny pattern %q conflicts with granted capability %q",
				deny.Pattern, grant.Pattern,
			)
		}
	}
	return nil
}

// capabilitiesConflict returns true if a grant and deny pattern overlap.
// Uses dot-separated segment matching with * as a wildcard segment.
func capabilitiesConflict(grant, deny string) bool {
	// Exact match is always a conflict.
	if grant == deny {
		return true
	}

	grantParts := strings.Split(grant, ".")
	denyParts := strings.Split(deny, ".")

	return segmentsConflict(grantParts, denyParts)
}

// segmentsConflict checks whether two dot-split capability patterns overlap.
// A trailing "*" segment matches any number of remaining segments.
func segmentsConflict(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == "*" || b[i] == "*" {
			return true
		}
		if a[i] != b[i] {
			return false
		}
	}
	// All compared segments matched. A conflict only when lengths are equal.
	return len(a) == len(b)
}

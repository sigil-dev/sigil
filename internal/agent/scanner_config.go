// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"github.com/sigil-dev/sigil/internal/config"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
)

// DefaultScannerModes is the single source of truth for scanner mode defaults.
// Input: block (reject prompt injection), Tool: flag (mark for review), Output: redact (strip secrets).
// DisableOriginTagging defaults to false (tagging enabled) — the zero value is the safe default.
var DefaultScannerModes = ScannerModes{
	Input:  types.ScannerModeBlock,
	Tool:   types.ScannerModeFlag,
	Output: types.ScannerModeRedact,
	// DisableOriginTagging omitted: false (enabled) is the correct default.
}

// parseAndSetMode parses a single scanner mode config field and assigns it to target.
// If raw is empty, target is set to fallback. Otherwise the value is validated.
func parseAndSetMode(raw types.ScannerMode, target *types.ScannerMode, fieldName string, fallback types.ScannerMode) error {
	if raw == "" {
		*target = fallback
		return nil
	}
	mode, err := types.ParseScannerMode(string(raw))
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner %s mode", fieldName)
	}
	*target = mode
	return nil
}

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to DefaultScannerModes. Non-empty fields are validated.
//
// DisableOriginTagging is copied directly from cfg: false (the default) means
// tagging is enabled; true means tagging is disabled. Both the config struct and
// ScannerModes use the same "disable" polarity so no inversion is needed.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
	var modes ScannerModes
	if err := parseAndSetMode(cfg.Input, &modes.Input, "input", DefaultScannerModes.Input); err != nil {
		return ScannerModes{}, err
	}
	if err := parseAndSetMode(cfg.Tool, &modes.Tool, "tool", DefaultScannerModes.Tool); err != nil {
		return ScannerModes{}, err
	}
	if err := parseAndSetMode(cfg.Output, &modes.Output, "output", DefaultScannerModes.Output); err != nil {
		return ScannerModes{}, err
	}
	modes.DisableOriginTagging = cfg.DisableOriginTagging
	if err := modes.Validate(); err != nil {
		return ScannerModes{}, err
	}
	return modes, nil
}

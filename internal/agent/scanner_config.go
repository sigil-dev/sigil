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

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to DefaultScannerModes. Non-empty fields are validated.
//
// DisableOriginTagging is copied directly from cfg: false (the default) means
// tagging is enabled; true means tagging is disabled. Both the config struct and
// ScannerModes use the same "disable" polarity so no inversion is needed.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
	var modes ScannerModes
	if cfg.Input != "" {
		m, err := types.ParseScannerMode(string(cfg.Input))
		if err != nil {
			return ScannerModes{}, sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner input mode")
		}
		modes.Input = m
	} else {
		modes.Input = DefaultScannerModes.Input
	}
	if cfg.Tool != "" {
		m, err := types.ParseScannerMode(string(cfg.Tool))
		if err != nil {
			return ScannerModes{}, sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner tool mode")
		}
		modes.Tool = m
	} else {
		modes.Tool = DefaultScannerModes.Tool
	}
	if cfg.Output != "" {
		m, err := types.ParseScannerMode(string(cfg.Output))
		if err != nil {
			return ScannerModes{}, sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner output mode")
		}
		modes.Output = m
	} else {
		modes.Output = DefaultScannerModes.Output
	}
	modes.DisableOriginTagging = cfg.DisableOriginTagging
	if err := modes.Validate(); err != nil {
		return ScannerModes{}, err
	}
	return modes, nil
}

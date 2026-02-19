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
	parseModeOrDefault := func(raw types.ScannerMode, def types.ScannerMode, field string) (types.ScannerMode, error) {
		if raw == "" {
			return def, nil
		}
		m, err := types.ParseScannerMode(string(raw))
		if err != nil {
			return "", sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner %s mode", field)
		}
		return m, nil
	}

	var modes ScannerModes
	var err error
	if modes.Input, err = parseModeOrDefault(cfg.Input, DefaultScannerModes.Input, "input"); err != nil {
		return ScannerModes{}, err
	}
	if modes.Tool, err = parseModeOrDefault(cfg.Tool, DefaultScannerModes.Tool, "tool"); err != nil {
		return ScannerModes{}, err
	}
	if modes.Output, err = parseModeOrDefault(cfg.Output, DefaultScannerModes.Output, "output"); err != nil {
		return ScannerModes{}, err
	}
	modes.DisableOriginTagging = cfg.DisableOriginTagging
	if err := modes.Validate(); err != nil {
		return ScannerModes{}, err
	}
	return modes, nil
}

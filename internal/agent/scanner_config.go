// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"github.com/sigil-dev/sigil/internal/config"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
)

// defaultScannerModes is the single source of truth for scanner mode defaults.
// Input: block (reject prompt injection), Tool: flag (mark for review), Output: redact (strip secrets).
// DisableOriginTagging defaults to false (tagging enabled) — the zero value is the safe default.
var defaultScannerModes = ScannerModes{
	Input:  types.ScannerModeBlock,
	Tool:   types.ScannerModeFlag,
	Output: types.ScannerModeRedact,
	// DisableOriginTagging omitted: false (enabled) is the correct default.
}

// parseModeField parses a single scanner mode config field.
// If raw is empty, fallback is returned. Otherwise the value is validated.
func parseModeField(raw types.ScannerMode, name string, fallback types.ScannerMode) (types.ScannerMode, error) {
	if raw == "" {
		return fallback, nil
	}
	mode, err := types.ParseScannerMode(string(raw))
	if err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner %s mode: %q", name, raw)
	}
	return mode, nil
}

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to defaultScannerModes. Non-empty fields are validated.
//
// DisableOriginTagging is copied directly from cfg: false (the default) means
// tagging is enabled; true means tagging is disabled. Both the config struct and
// ScannerModes use the same "disable" polarity so no inversion is needed.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
	type modeEntry struct {
		raw      types.ScannerMode
		name     string
		fallback types.ScannerMode
		dst      *types.ScannerMode
	}
	var modes ScannerModes
	for _, e := range []modeEntry{
		{cfg.Input, "input", defaultScannerModes.Input, &modes.Input},
		{cfg.Tool, "tool", defaultScannerModes.Tool, &modes.Tool},
		{cfg.Output, "output", defaultScannerModes.Output, &modes.Output},
	} {
		parsed, err := parseModeField(e.raw, e.name, e.fallback)
		if err != nil {
			return ScannerModes{}, err
		}
		*e.dst = parsed
	}
	modes.DisableOriginTagging = cfg.DisableOriginTagging
	return modes, nil
}

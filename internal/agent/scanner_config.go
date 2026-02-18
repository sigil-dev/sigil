// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// defaultScannerModes is the single source of truth for scanner mode defaults.
// Input: block (reject prompt injection), Tool: flag (mark for review), Output: redact (strip secrets).
// DisableOriginTagging defaults to false (tagging enabled) — the zero value is the safe default.
var defaultScannerModes = ScannerModes{
	Input:  scanner.ModeBlock,
	Tool:   scanner.ModeFlag,
	Output: scanner.ModeRedact,
	// DisableOriginTagging omitted: false (enabled) is the correct default.
}

// parseModeField parses a single scanner mode config field.
// If raw is empty, fallback is returned. Otherwise the value is validated.
func parseModeField(raw scanner.Mode, name string, fallback scanner.Mode) (scanner.Mode, error) {
	if raw == "" {
		return fallback, nil
	}
	if !raw.Valid() {
		return "", sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner %s mode: %q", name, raw)
	}
	return scanner.Mode(raw), nil
}

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to defaultScannerModes. Non-empty fields are validated.
//
// DisableOriginTagging is copied directly from cfg: false (the default) means
// tagging is enabled; true means tagging is disabled. Both the config struct and
// ScannerModes use the same "disable" polarity so no inversion is needed.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
	var (
		modes ScannerModes
		err   error
	)
	if modes.Input, err = parseModeField(cfg.Input, "input", defaultScannerModes.Input); err != nil {
		return ScannerModes{}, err
	}
	if modes.Tool, err = parseModeField(cfg.Tool, "tool", defaultScannerModes.Tool); err != nil {
		return ScannerModes{}, err
	}
	if modes.Output, err = parseModeField(cfg.Output, "output", defaultScannerModes.Output); err != nil {
		return ScannerModes{}, err
	}
	modes.DisableOriginTagging = cfg.DisableOriginTagging
	return modes, nil
}

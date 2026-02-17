// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// defaultScannerModes is the single source of truth for scanner mode defaults.
// Input: block (reject prompt injection), Tool: flag (log and continue, per D062), Output: redact (strip secrets).
var defaultScannerModes = ScannerModes{
	Input:  scanner.ModeBlock,
	Tool:   scanner.ModeFlag,
	Output: scanner.ModeRedact,
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
	return modes, nil
}

// DefaultLoopConfig returns a LoopConfig with default scanner modes and the given required dependencies.
// Returns an error if any required dependency is nil.
func DefaultLoopConfig(sessions *SessionManager, enforcer *security.Enforcer, router provider.Router, sc scanner.Scanner) (LoopConfig, error) {
	return NewLoopConfig(sessions, enforcer, router, sc, defaultScannerModes)
}

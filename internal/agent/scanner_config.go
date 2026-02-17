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

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to defaultScannerModes. Non-empty fields are validated.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
	modes := defaultScannerModes

	if cfg.Input != "" {
		if !cfg.Input.Valid() {
			return ScannerModes{}, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner input mode: %q", cfg.Input)
		}
		modes.Input = scanner.Mode(cfg.Input)
	}
	if cfg.Tool != "" {
		if !cfg.Tool.Valid() {
			return ScannerModes{}, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner tool mode: %q", cfg.Tool)
		}
		modes.Tool = scanner.Mode(cfg.Tool)
	}
	if cfg.Output != "" {
		if !cfg.Output.Valid() {
			return ScannerModes{}, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner output mode: %q", cfg.Output)
		}
		modes.Output = scanner.Mode(cfg.Output)
	}
	return modes, nil
}

// DefaultLoopConfig returns a LoopConfig with default scanner modes and the given required dependencies.
// Returns an error if any required dependency is nil.
func DefaultLoopConfig(sessions *SessionManager, enforcer *security.Enforcer, router provider.Router, sc scanner.Scanner) (LoopConfig, error) {
	return NewLoopConfig(sessions, enforcer, router, sc, defaultScannerModes)
}

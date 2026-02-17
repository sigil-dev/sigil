// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/security/scanner"
)

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Config fields are types.ScannerMode; scanner.Mode is an alias so the conversion is direct.
// Empty fields default to the standard modes: block (input), flag (tool), redact (output).
func NewScannerModesFromConfig(cfg config.ScannerConfig) ScannerModes {
	input := scanner.Mode(cfg.Input)
	if input == "" {
		input = scanner.ModeBlock
	}
	tool := scanner.Mode(cfg.Tool)
	if tool == "" {
		tool = scanner.ModeFlag
	}
	output := scanner.Mode(cfg.Output)
	if output == "" {
		output = scanner.ModeRedact
	}
	return ScannerModes{
		Input:  input,
		Tool:   tool,
		Output: output,
	}
}

// DefaultLoopConfig returns a LoopConfig with default scanner modes and the given required dependencies.
func DefaultLoopConfig(sessions *SessionManager, enforcer *security.Enforcer, router provider.Router, sc scanner.Scanner) LoopConfig {
	return LoopConfig{
		SessionManager: sessions,
		Enforcer:       enforcer,
		ProviderRouter: router,
		Scanner:        sc,
		ScannerModes: ScannerModes{
			Input:  scanner.ModeBlock,
			Tool:   scanner.ModeFlag,
			Output: scanner.ModeRedact,
		},
	}
}

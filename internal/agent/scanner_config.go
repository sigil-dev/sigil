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
//
// WARNING: Tool stage uses ScannerModeFlag by default (D062 availability tradeoff).
//
// ScannerModeFlag detects injection patterns in tool results and emits structured log
// entries, but it does NOT block or modify the content. Tool results containing injection
// patterns are passed through to the LLM unmodified. This is an intentional tradeoff:
// blocking tool results breaks agent workflows when tools return content that resembles
// injection syntax (e.g., formatted output, code, structured data).
//
// Operators who require blocking defense at the tool stage MUST explicitly set the
// Tool mode to ScannerModeBlock or ScannerModeRedact in their sigil.yaml:
//
//	scanner:
//	  tool: block    # reject tool results containing injection patterns
//	  tool: redact   # strip injection patterns from tool results before passing to LLM
//
// See D062 and D073 in docs/decisions/decision-log.md for the full rationale.
var DefaultScannerModes = ScannerModes{
	Input:  types.ScannerModeBlock,
	Tool:   types.ScannerModeFlag,
	Output: types.ScannerModeRedact,
	// DisableOriginTagging omitted: false (enabled) is the correct default.
}

// parseModeOrDefault returns def if raw is empty, otherwise parses and validates raw.
// field is used in error messages to identify which scanner mode field failed validation.
func parseModeOrDefault(raw types.ScannerMode, def types.ScannerMode, field string) (types.ScannerMode, error) {
	if raw == "" {
		return def, nil
	}
	m, err := types.ParseScannerMode(string(raw))
	if err != nil {
		return "", sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue, "scanner %s mode", field)
	}
	return m, nil
}

// NewScannerModesFromConfig converts config.ScannerConfig to agent.ScannerModes.
// Empty fields fall back to DefaultScannerModes. Non-empty fields are validated.
//
// DisableOriginTagging is copied directly from cfg: false (the default) means
// tagging is enabled; true means tagging is disabled. Both the config struct and
// ScannerModes use the same "disable" polarity so no inversion is needed.
func NewScannerModesFromConfig(cfg config.ScannerConfig) (ScannerModes, error) {
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
	// NOTE: AllowPermissiveInputMode is intentionally not copied here.
	// It is an admission gate enforced by config.Validate() before this
	// function is called. See config.go Validate() for the permissive
	// input mode check.
	if err := modes.Validate(); err != nil {
		return ScannerModes{}, err
	}
	return modes, nil
}

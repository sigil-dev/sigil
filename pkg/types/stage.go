// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package types

// ScanStage identifies where in the agent pipeline a security scan occurs.
type ScanStage string

const (
	// ScanStageInput is the stage for scanning user or channel input.
	ScanStageInput ScanStage = "input"
	// ScanStageTool is the stage for scanning tool call arguments or results.
	ScanStageTool ScanStage = "tool"
	// ScanStageOutput is the stage for scanning LLM output before delivery.
	ScanStageOutput ScanStage = "output"
)

// Valid reports whether the scan stage is a known pipeline stage.
func (s ScanStage) Valid() bool {
	switch s {
	case ScanStageInput, ScanStageTool, ScanStageOutput:
		return true
	default:
		return false
	}
}

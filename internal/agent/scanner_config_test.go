// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestNewScannerModesFromConfig tests that NewScannerModesFromConfig correctly
// converts config.ScannerConfig fields to agent.ScannerModes.
// It covers explicit values and the default-filling behavior for empty fields.
func TestNewScannerModesFromConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ScannerConfig
		want agent.ScannerModes
	}{
		{
			name: "all fields set explicitly",
			cfg: config.ScannerConfig{
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeFlag,
				Output: types.ScannerModeRedact,
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeBlock,
				Tool:   scanner.ModeFlag,
				Output: scanner.ModeRedact,
			},
		},
		{
			name: "all fields set to non-default values",
			cfg: config.ScannerConfig{
				Input:  types.ScannerModeFlag,
				Tool:   types.ScannerModeRedact,
				Output: types.ScannerModeBlock,
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeFlag,
				Tool:   scanner.ModeRedact,
				Output: scanner.ModeBlock,
			},
		},
		{
			name: "empty config uses defaults: block/flag/redact",
			cfg:  config.ScannerConfig{},
			want: agent.ScannerModes{
				Input:  scanner.ModeBlock,
				Tool:   scanner.ModeFlag,
				Output: scanner.ModeRedact,
			},
		},
		{
			name: "only input empty uses default block",
			cfg: config.ScannerConfig{
				Input:  "",
				Tool:   types.ScannerModeRedact,
				Output: types.ScannerModeBlock,
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeBlock,
				Tool:   scanner.ModeRedact,
				Output: scanner.ModeBlock,
			},
		},
		{
			name: "only tool empty uses default flag",
			cfg: config.ScannerConfig{
				Input:  types.ScannerModeRedact,
				Tool:   "",
				Output: types.ScannerModeBlock,
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeRedact,
				Tool:   scanner.ModeFlag,
				Output: scanner.ModeBlock,
			},
		},
		{
			name: "only output empty uses default redact",
			cfg: config.ScannerConfig{
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeBlock,
				Output: "",
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeBlock,
				Tool:   scanner.ModeBlock,
				Output: scanner.ModeRedact,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agent.NewScannerModesFromConfig(tt.cfg)
			assert.Equal(t, tt.want.Input, got.Input, "Input mode mismatch")
			assert.Equal(t, tt.want.Tool, got.Tool, "Tool mode mismatch")
			assert.Equal(t, tt.want.Output, got.Output, "Output mode mismatch")
		})
	}
}

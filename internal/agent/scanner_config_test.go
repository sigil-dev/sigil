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
	"github.com/stretchr/testify/require"
)

// TestNewScannerModesFromConfig tests that NewScannerModesFromConfig correctly
// converts config.ScannerConfig fields to agent.ScannerModes.
// It covers explicit values, default-filling behavior for empty fields, and validation errors.
func TestNewScannerModesFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.ScannerConfig
		want    agent.ScannerModes
		wantErr bool
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
			name: "empty config uses defaults: block/block/redact",
			cfg:  config.ScannerConfig{},
			want: agent.ScannerModes{
				Input:  scanner.ModeBlock,
				Tool:   scanner.ModeBlock,
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
			name: "only tool empty uses default block",
			cfg: config.ScannerConfig{
				Input:  types.ScannerModeRedact,
				Tool:   "",
				Output: types.ScannerModeBlock,
			},
			want: agent.ScannerModes{
				Input:  scanner.ModeRedact,
				Tool:   scanner.ModeBlock,
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
		{
			name: "invalid input mode returns error",
			cfg: config.ScannerConfig{
				Input: "bogus",
			},
			wantErr: true,
		},
		{
			name: "invalid tool mode returns error",
			cfg: config.ScannerConfig{
				Tool: "bogus",
			},
			wantErr: true,
		},
		{
			name: "invalid output mode returns error",
			cfg: config.ScannerConfig{
				Output: "bogus",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := agent.NewScannerModesFromConfig(tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Input, got.Input, "Input mode mismatch")
			assert.Equal(t, tt.want.Tool, got.Tool, "Tool mode mismatch")
			assert.Equal(t, tt.want.Output, got.Output, "Output mode mismatch")
		})
	}
}

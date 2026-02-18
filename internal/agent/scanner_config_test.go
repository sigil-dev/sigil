// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/config"
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
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeFlag,
				Output: types.ScannerModeRedact,
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
				Input:  types.ScannerModeFlag,
				Tool:   types.ScannerModeRedact,
				Output: types.ScannerModeBlock,
			},
		},
		{
			name: "empty config uses defaults: block/flag/redact",
			cfg:  config.ScannerConfig{},
			want: agent.ScannerModes{
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeFlag,
				Output: types.ScannerModeRedact,
				// DisableOriginTagging defaults to false (tagging enabled) — zero-value.
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
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeRedact,
				Output: types.ScannerModeBlock,
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
				Input:  types.ScannerModeRedact,
				Tool:   types.ScannerModeFlag,
				Output: types.ScannerModeBlock,
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
				Input:  types.ScannerModeBlock,
				Tool:   types.ScannerModeBlock,
				Output: types.ScannerModeRedact,
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
			assert.Equal(t, tt.want.DisableOriginTagging, got.DisableOriginTagging, "DisableOriginTagging mismatch")
		})
	}
}

// TestNewScannerModesFromConfig_DisableOriginTagging tests that the DisableOriginTagging
// field is correctly propagated from config.ScannerConfig to agent.ScannerModes.
// Semantics: DisableOriginTagging=false means tagging IS enabled (zero-value default).
// DisableOriginTagging=true means tagging IS disabled.
func TestNewScannerModesFromConfig_DisableOriginTagging(t *testing.T) {
	tests := []struct {
		name                 string
		disableOriginTagging bool
		want                 bool
	}{
		{
			name:                 "origin tagging enabled (disable=false)",
			disableOriginTagging: false,
			want:                 false,
		},
		{
			name:                 "origin tagging disabled (disable=true)",
			disableOriginTagging: true,
			want:                 true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.ScannerConfig{
				Input:                types.ScannerModeBlock,
				Tool:                 types.ScannerModeFlag,
				Output:               types.ScannerModeRedact,
				DisableOriginTagging: tt.disableOriginTagging,
			}
			got, err := agent.NewScannerModesFromConfig(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.DisableOriginTagging)
		})
	}
}

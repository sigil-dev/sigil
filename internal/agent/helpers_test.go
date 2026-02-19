// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/pkg/types"
)

func TestBuildBlockedAuditEntry(t *testing.T) {
	baseMsg := agent.InboundMessage{
		SessionID:   "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Content:     "hello",
	}

	tests := []struct {
		name            string
		action          string
		threatInfo      *store.ThreatInfo
		reason          string
		extraDetails    map[string]any
		wantResult      string
		wantScannerErr  bool
		wantThreatKey   bool
		wantNoThreatKey bool
	}{
		{
			name:           "nil threatInfo sets scanner_error",
			action:         "agent_loop.input_blocked",
			threatInfo:     nil,
			reason:         "scanner_failure",
			extraDetails:   nil,
			wantResult:     "scanner_failure",
			wantScannerErr: true,
		},
		{
			name:          "detected threat sets threat_detected, threat_rules, threat_stage",
			action:        "agent_loop.input_blocked",
			threatInfo:    store.NewThreatDetected(types.ScanStageInput, []string{"rule-abc"}),
			reason:        "blocked_threat",
			extraDetails:  nil,
			wantResult:    "blocked_threat",
			wantThreatKey: true,
		},
		{
			name:            "bypassed scan (not detected) does not set threat_detected",
			action:          "agent_loop.input_blocked",
			threatInfo:      store.NewBypassedScan(types.ScanStageTool),
			reason:          "scanner_failure",
			extraDetails:    nil,
			wantResult:      "scanner_failure",
			wantNoThreatKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := agent.ExportBuildBlockedAuditEntry(tt.action, baseMsg, tt.threatInfo, tt.reason, tt.extraDetails)
			require.NotNil(t, entry)

			assert.Equal(t, tt.action, entry.Action)
			assert.Equal(t, baseMsg.UserID, entry.Actor)
			assert.Equal(t, baseMsg.WorkspaceID, entry.WorkspaceID)
			assert.Equal(t, baseMsg.SessionID, entry.SessionID)
			assert.Equal(t, tt.wantResult, entry.Result)
			assert.NotEmpty(t, entry.ID)
			assert.False(t, entry.Timestamp.IsZero())

			if tt.wantScannerErr {
				v, ok := entry.Details["scanner_error"]
				assert.True(t, ok, "expected scanner_error key in details")
				assert.Equal(t, true, v)
				_, hasThreat := entry.Details["threat_detected"]
				assert.False(t, hasThreat, "scanner_error case must not have threat_detected")
			}

			if tt.wantThreatKey {
				v, ok := entry.Details["threat_detected"]
				assert.True(t, ok, "expected threat_detected key in details")
				assert.Equal(t, true, v)
				_, hasRules := entry.Details["threat_rules"]
				assert.True(t, hasRules, "expected threat_rules key in details")
				_, hasStage := entry.Details["threat_stage"]
				assert.True(t, hasStage, "expected threat_stage key in details")
			}

			if tt.wantNoThreatKey {
				_, hasThreat := entry.Details["threat_detected"]
				assert.False(t, hasThreat, "bypassed scan must not set threat_detected")
				_, hasScannerErr := entry.Details["scanner_error"]
				assert.False(t, hasScannerErr, "bypassed scan must not set scanner_error")
			}
		})
	}
}

func TestBuildBlockedAuditEntry_EmptyReason(t *testing.T) {
	msg := agent.InboundMessage{
		SessionID:   "sess-2",
		WorkspaceID: "ws-2",
		UserID:      "user-2",
		Content:     "test",
	}
	entry := agent.ExportBuildBlockedAuditEntry("agent_loop.output_blocked", msg, nil, "", nil)
	require.NotNil(t, entry)
	assert.Equal(t, "blocked", entry.Result, "empty reason should default to 'blocked'")
}

func TestBuildBlockedAuditEntry_ExtraDetailsMerged(t *testing.T) {
	msg := agent.InboundMessage{
		SessionID:   "sess-3",
		WorkspaceID: "ws-3",
		UserID:      "user-3",
		Content:     "test",
	}
	extra := map[string]any{"stage": "input", "custom_key": 42}
	entry := agent.ExportBuildBlockedAuditEntry("agent_loop.input_blocked", msg, nil, "scanner_failure", extra)
	require.NotNil(t, entry)
	assert.Equal(t, "input", entry.Details["stage"])
	assert.Equal(t, 42, entry.Details["custom_key"])
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		name     string
		severity scanner.Severity
		want     int
	}{
		{"high", scanner.SeverityHigh, 3},
		{"medium", scanner.SeverityMedium, 2},
		{"low", scanner.SeverityLow, 1},
		{"unknown string", scanner.Severity("unknown"), 0},
		{"empty string", scanner.Severity(""), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.severity.Rank()
			assert.Equal(t, tt.want, got)
		})
	}
}

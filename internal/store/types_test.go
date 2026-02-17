// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStatusValues(t *testing.T) {
	assert.Equal(t, store.SessionStatus("active"), store.SessionStatusActive)
	assert.Equal(t, store.SessionStatus("paused"), store.SessionStatusPaused)
	assert.Equal(t, store.SessionStatus("archived"), store.SessionStatusArchived)
}

func TestMessageRoleValues(t *testing.T) {
	assert.Equal(t, store.MessageRole("user"), store.MessageRoleUser)
	assert.Equal(t, store.MessageRole("assistant"), store.MessageRoleAssistant)
	assert.Equal(t, store.MessageRole("system"), store.MessageRoleSystem)
	assert.Equal(t, store.MessageRole("tool"), store.MessageRoleTool)
}

func TestListOptsDefaults(t *testing.T) {
	opts := store.ListOpts{}
	assert.Equal(t, 0, opts.Limit)
	assert.Equal(t, 0, opts.Offset)
}

func TestSearchOptsFields(t *testing.T) {
	opts := store.SearchOpts{
		Limit:  10,
		Offset: 0,
	}
	assert.Equal(t, 10, opts.Limit)
}

func TestVectorResultFields(t *testing.T) {
	result := store.VectorResult{
		ID:       "vec-1",
		Score:    0.95,
		Metadata: map[string]any{"source": "test"},
	}
	assert.Equal(t, "vec-1", result.ID)
	assert.InDelta(t, 0.95, result.Score, 0.001)
}

func TestEntityFields(t *testing.T) {
	entity := store.Entity{
		ID:          "ent-1",
		WorkspaceID: "ws-1",
		Type:        "person",
		Name:        "Alice",
		Properties:  map[string]any{"role": "engineer"},
		CreatedAt:   time.Now(),
	}
	assert.Equal(t, "person", entity.Type)
}

// --- SessionStatus.Valid ---

func TestSessionStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status store.SessionStatus
		want   bool
	}{
		{"active", store.SessionStatusActive, true},
		{"paused", store.SessionStatusPaused, true},
		{"archived", store.SessionStatusArchived, true},
		{"empty", "", false},
		{"unknown", store.SessionStatus("unknown"), false},
		{"completed", store.SessionStatus("completed"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.status.Valid())
		})
	}
}

// --- MessageRole.Valid ---

func TestMessageRole_Valid(t *testing.T) {
	tests := []struct {
		name string
		role store.MessageRole
		want bool
	}{
		{"user", store.MessageRoleUser, true},
		{"assistant", store.MessageRoleAssistant, true},
		{"system", store.MessageRoleSystem, true},
		{"tool", store.MessageRoleTool, true},
		{"empty", "", false},
		{"unknown", store.MessageRole("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.Valid())
		})
	}
}

// --- Session.Validate ---

func TestSession_Validate(t *testing.T) {
	now := time.Now()
	validSession := store.Session{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   now,
	}

	tests := []struct {
		name    string
		mutate  func(s *store.Session)
		wantErr bool
	}{
		{"valid", func(s *store.Session) {}, false},
		{"missing ID", func(s *store.Session) { s.ID = "" }, true},
		{"missing WorkspaceID", func(s *store.Session) { s.WorkspaceID = "" }, true},
		{"missing UserID", func(s *store.Session) { s.UserID = "" }, true},
		{"invalid status", func(s *store.Session) { s.Status = "bogus" }, true},
		{"zero CreatedAt", func(s *store.Session) { s.CreatedAt = time.Time{} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validSession
			tt.mutate(&s)
			err := s.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err), "expected IsInvalidInput, got: %v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- NewToolBudget ---

func TestNewToolBudget(t *testing.T) {
	tests := []struct {
		name       string
		maxPerTurn int
		maxPerSess int
		wantErr    bool
	}{
		{"valid zeros", 0, 0, false},
		{"valid positive", 5, 100, false},
		{"negative turn", -1, 10, true},
		{"negative session", 5, -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := store.NewToolBudget(tt.maxPerTurn, tt.maxPerSess)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.maxPerTurn, b.MaxCallsPerTurn)
				assert.Equal(t, tt.maxPerSess, b.MaxCallsPerSession)
				assert.Equal(t, 0, b.Used)
			}
		})
	}
}

// --- ToolBudget.Validate ---

func TestToolBudget_Validate(t *testing.T) {
	tests := []struct {
		name    string
		budget  store.ToolBudget
		wantErr bool
	}{
		{"zero values", store.ToolBudget{}, false},
		{"valid with usage", store.ToolBudget{MaxCallsPerTurn: 5, MaxCallsPerSession: 100, Used: 50}, false},
		{"used equals max session", store.ToolBudget{MaxCallsPerSession: 10, Used: 10}, false},
		{"negative max turn", store.ToolBudget{MaxCallsPerTurn: -1}, true},
		{"negative max session", store.ToolBudget{MaxCallsPerSession: -1}, true},
		{"negative used", store.ToolBudget{Used: -1}, true},
		{"used exceeds max session", store.ToolBudget{MaxCallsPerSession: 10, Used: 11}, true},
		// When max is 0 (unlimited), used > 0 is fine.
		{"unlimited session with usage", store.ToolBudget{MaxCallsPerSession: 0, Used: 999}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.budget.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- NewTokenBudget ---

func TestNewTokenBudget(t *testing.T) {
	tests := []struct {
		name       string
		maxSession int
		maxHour    int
		maxDay     int
		wantErr    bool
	}{
		{"valid zeros", 0, 0, 0, false},
		{"valid positive", 1000, 500, 2000, false},
		{"negative session", -1, 0, 0, true},
		{"negative hour", 0, -1, 0, true},
		{"negative day", 0, 0, -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := store.NewTokenBudget(tt.maxSession, tt.maxHour, tt.maxDay)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.maxSession, b.MaxPerSession)
				assert.Equal(t, tt.maxHour, b.MaxPerHour)
				assert.Equal(t, tt.maxDay, b.MaxPerDay)
			}
		})
	}
}

// --- TokenBudget.Validate ---

func TestTokenBudget_Validate(t *testing.T) {
	tests := []struct {
		name    string
		budget  store.TokenBudget
		wantErr bool
	}{
		{"zero values", store.TokenBudget{}, false},
		{"valid with usage", store.TokenBudget{MaxPerSession: 1000, MaxPerHour: 500, MaxPerDay: 2000, UsedSession: 100, UsedHour: 50, UsedDay: 200}, false},
		{"negative max session", store.TokenBudget{MaxPerSession: -1}, true},
		{"negative max hour", store.TokenBudget{MaxPerHour: -1}, true},
		{"negative max day", store.TokenBudget{MaxPerDay: -1}, true},
		{"negative used session", store.TokenBudget{UsedSession: -1}, true},
		{"negative used hour", store.TokenBudget{UsedHour: -1}, true},
		{"negative used day", store.TokenBudget{UsedDay: -1}, true},
		{"used session exceeds max", store.TokenBudget{MaxPerSession: 100, UsedSession: 101}, true},
		{"used hour exceeds max", store.TokenBudget{MaxPerHour: 100, UsedHour: 101}, true},
		{"used day exceeds max", store.TokenBudget{MaxPerDay: 100, UsedDay: 101}, true},
		// Unlimited (max=0) allows any usage.
		{"unlimited with usage", store.TokenBudget{MaxPerSession: 0, UsedSession: 999}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.budget.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- ThreatInfo.Validate ---

func TestThreatInfo_Validate(t *testing.T) {
	tests := []struct {
		name    string
		threat  store.ThreatInfo
		wantErr bool
	}{
		{"not detected, no rules", store.ThreatInfo{Detected: false, Rules: nil}, false},
		{"not detected, empty rules", store.ThreatInfo{Detected: false, Rules: []string{}}, false},
		{"detected with rules", store.ThreatInfo{Detected: true, Rules: []string{"rule-1"}}, false},
		{"detected no rules", store.ThreatInfo{Detected: true, Rules: nil}, false},
		{"not detected with rules", store.ThreatInfo{Detected: false, Rules: []string{"rule-1"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.threat.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- Message.Validate ---

func TestMessage_Validate(t *testing.T) {
	validMsg := store.Message{
		ID:        "msg-1",
		SessionID: "sess-1",
		Role:      store.MessageRoleUser,
		Content:   "hello",
	}

	tests := []struct {
		name    string
		mutate  func(m *store.Message)
		wantErr bool
	}{
		{"valid user", func(m *store.Message) {}, false},
		{"valid assistant", func(m *store.Message) { m.Role = store.MessageRoleAssistant }, false},
		{"valid system", func(m *store.Message) { m.Role = store.MessageRoleSystem }, false},
		{
			"valid tool role",
			func(m *store.Message) {
				m.Role = store.MessageRoleTool
				m.Content = ""
				m.ToolCallID = "call-1"
				m.ToolName = "my_tool"
			},
			false,
		},
		{"missing ID", func(m *store.Message) { m.ID = "" }, true},
		{"missing SessionID", func(m *store.Message) { m.SessionID = "" }, true},
		{"invalid role", func(m *store.Message) { m.Role = "unknown" }, true},
		{"empty content for user", func(m *store.Message) { m.Content = "" }, true},
		{
			"tool call id without name",
			func(m *store.Message) {
				m.ToolCallID = "call-1"
				m.ToolName = ""
			},
			true,
		},
		{
			"tool name without call id",
			func(m *store.Message) {
				m.ToolCallID = ""
				m.ToolName = "my_tool"
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validMsg
			tt.mutate(&m)
			err := m.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.IsInvalidInput(err), "expected IsInvalidInput, got: %v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

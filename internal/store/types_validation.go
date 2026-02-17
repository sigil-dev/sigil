// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import (
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Valid reports whether the status is a known session lifecycle state.
func (s SessionStatus) Valid() bool {
	switch s {
	case SessionStatusActive, SessionStatusPaused, SessionStatusArchived:
		return true
	default:
		return false
	}
}

// Valid reports whether the role is a known message role.
func (r MessageRole) Valid() bool {
	switch r {
	case MessageRoleUser, MessageRoleAssistant, MessageRoleSystem, MessageRoleTool:
		return true
	default:
		return false
	}
}

// Validate checks that the Session has all required fields set correctly.
func (s Session) Validate() error {
	if s.ID == "" {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "session: ID is required")
	}
	if s.WorkspaceID == "" {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "session: WorkspaceID is required")
	}
	if s.UserID == "" {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "session: UserID is required")
	}
	if !s.Status.Valid() {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "session: invalid status %q", s.Status)
	}
	if s.CreatedAt.IsZero() {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "session: CreatedAt is required")
	}
	return nil
}

// NewToolBudget creates a ToolBudget with the given max limits, returning an
// error if any max value is negative.
func NewToolBudget(maxPerTurn, maxPerSession int) (ToolBudget, error) {
	b := ToolBudget{MaxCallsPerTurn: maxPerTurn, MaxCallsPerSession: maxPerSession}
	if err := b.Validate(); err != nil {
		return ToolBudget{}, err
	}
	return b, nil
}

// Validate checks that the ToolBudget has self-consistent values.
func (b ToolBudget) Validate() error {
	if b.MaxCallsPerTurn < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "tool budget: MaxCallsPerTurn must be >= 0, got %d", b.MaxCallsPerTurn)
	}
	if b.MaxCallsPerSession < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "tool budget: MaxCallsPerSession must be >= 0, got %d", b.MaxCallsPerSession)
	}
	if b.Used < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "tool budget: Used must be >= 0, got %d", b.Used)
	}
	if b.MaxCallsPerSession > 0 && b.Used > b.MaxCallsPerSession {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "tool budget: Used (%d) exceeds MaxCallsPerSession (%d)", b.Used, b.MaxCallsPerSession)
	}
	return nil
}

// NewTokenBudget creates a TokenBudget with the given max limits, returning an
// error if any max value is negative.
func NewTokenBudget(maxPerSession, maxPerHour, maxPerDay int) (TokenBudget, error) {
	b := TokenBudget{MaxPerSession: maxPerSession, MaxPerHour: maxPerHour, MaxPerDay: maxPerDay}
	if err := b.Validate(); err != nil {
		return TokenBudget{}, err
	}
	return b, nil
}

// Validate checks that the TokenBudget has self-consistent values.
func (b TokenBudget) Validate() error {
	if b.MaxPerSession < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: MaxPerSession must be >= 0, got %d", b.MaxPerSession)
	}
	if b.MaxPerHour < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: MaxPerHour must be >= 0, got %d", b.MaxPerHour)
	}
	if b.MaxPerDay < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: MaxPerDay must be >= 0, got %d", b.MaxPerDay)
	}
	if b.UsedSession < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedSession must be >= 0, got %d", b.UsedSession)
	}
	if b.UsedHour < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedHour must be >= 0, got %d", b.UsedHour)
	}
	if b.UsedDay < 0 {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedDay must be >= 0, got %d", b.UsedDay)
	}
	if b.MaxPerSession > 0 && b.UsedSession > b.MaxPerSession {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedSession (%d) exceeds MaxPerSession (%d)", b.UsedSession, b.MaxPerSession)
	}
	if b.MaxPerHour > 0 && b.UsedHour > b.MaxPerHour {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedHour (%d) exceeds MaxPerHour (%d)", b.UsedHour, b.MaxPerHour)
	}
	if b.MaxPerDay > 0 && b.UsedDay > b.MaxPerDay {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "token budget: UsedDay (%d) exceeds MaxPerDay (%d)", b.UsedDay, b.MaxPerDay)
	}
	return nil
}

// Validate checks ThreatInfo invariants: if Detected is false, Rules must be empty.
func (t ThreatInfo) Validate() error {
	if !t.Detected && len(t.Rules) > 0 {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "threat info: Rules must be empty when Detected is false")
	}
	return nil
}

// Validate checks that the Message has all required fields set correctly.
func (m Message) Validate() error {
	if m.ID == "" {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "message: ID is required")
	}
	if m.SessionID == "" {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "message: SessionID is required")
	}
	if !m.Role.Valid() {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "message: invalid role %q", m.Role)
	}
	// Tool role uses ToolCallID/ToolName instead of Content; all other roles require Content.
	if m.Role != MessageRoleTool && m.Content == "" {
		return sigilerr.Errorf(sigilerr.CodeStoreInvalidInput, "message: Content is required for role %q", m.Role)
	}
	// ToolCallID and ToolName must both be set or both be empty.
	if (m.ToolCallID == "") != (m.ToolName == "") {
		return sigilerr.New(sigilerr.CodeStoreInvalidInput, "message: ToolCallID and ToolName must both be set or both be empty")
	}
	return nil
}

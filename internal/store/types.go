// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import (
	"time"

	"github.com/sigil-dev/sigil/pkg/types"
)

// --- Session types ---

// SessionStatus represents the lifecycle state of an agent session.
type SessionStatus string

const (
	SessionStatusActive   SessionStatus = "active"
	SessionStatusPaused   SessionStatus = "paused"
	SessionStatusArchived SessionStatus = "archived"
)

// Session represents an agent conversation session within a workspace.
type Session struct {
	ID             string
	WorkspaceID    string
	UserID         string
	Summary        string
	LastCompaction time.Time
	ModelOverride  string
	ToolBudget     ToolBudget
	TokenBudget    TokenBudget
	Status         SessionStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ToolBudget tracks tool call limits for a session.
type ToolBudget struct {
	MaxCallsPerTurn    int
	MaxCallsPerSession int
	Used               int
}

// TokenBudget tracks token usage limits across time windows.
type TokenBudget struct {
	MaxPerSession int
	MaxPerHour    int
	MaxPerDay     int
	UsedSession   int
	UsedHour      int
	UsedDay       int
}

// --- Message types ---

// MessageRole identifies the sender of a message in a session.
type MessageRole string

const (
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleSystem    MessageRole = "system"
	MessageRoleTool      MessageRole = "tool"
)

// ScanStage identifies the pipeline stage where a security scan occurred.
// Aliased from pkg/types for backward compatibility.
type ScanStage = types.ScanStage

const (
	ScanStageInput  ScanStage = types.ScanStageInput
	ScanStageTool   ScanStage = types.ScanStageTool
	ScanStageOutput ScanStage = types.ScanStageOutput
)

// ThreatInfo records security scanner findings for audit persistence.
//
// Callers MUST distinguish three semantic states via pointer nilness:
//   - nil *ThreatInfo: scanner did not run (legacy message or pre-scanner code path)
//   - &ThreatInfo{Detected: false}: scanner ran and found no threats
//   - &ThreatInfo{Detected: true, ...}: scanner detected threats
//
// Note: JSON serialization does not preserve the nil vs empty distinction — both
// nil and &ThreatInfo{} serialize to `{}`. This is a known limitation for audit
// queries on historical data; callers relying on nil-as-unscanned semantics MUST
// use the in-memory representation rather than round-tripping through JSON.
type ThreatInfo struct {
	Detected bool      `json:"detected"`
	Rules    []string  `json:"rules"`
	Stage    ScanStage `json:"stage"`
	// Bypassed is true when the scanner was unavailable and content passed
	// through unscanned (best-effort path below circuit breaker threshold).
	// Detected will be false because no scan occurred, not because the
	// content is clean. Audit queries MUST treat Bypassed=true as distinct
	// from a confirmed clean scan result.
	Bypassed bool `json:"bypassed,omitempty"`
}

// Message represents a single message in a session conversation.
type Message struct {
	ID         string
	SessionID  string
	Role       MessageRole
	Content    string
	ToolCallID string
	ToolName   string
	// Origin records the source of the message for audit purposes.
	// Values: "user_input", "system", "tool_output" (mirrors pkg/types.Origin).
	// Stored as a plain string to avoid coupling store to provider or types packages.
	Origin    string
	Threat    *ThreatInfo
	CreatedAt time.Time
	Metadata  map[string]string
}

// --- Memory types ---

// Summary represents a compacted summary of a range of messages.
type Summary struct {
	ID          string
	WorkspaceID string
	FromTime    time.Time
	ToTime      time.Time
	Content     string
	MessageIDs  []string
	CreatedAt   time.Time
}

// Entity represents a named entity extracted from conversations.
type Entity struct {
	ID          string
	WorkspaceID string
	Type        string
	Name        string
	Properties  map[string]any
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Relationship represents a directed edge between two entities.
type Relationship struct {
	ID       string
	FromID   string
	ToID     string
	Type     string
	Metadata map[string]any
}

// Fact represents a predicate-value assertion about an entity.
type Fact struct {
	ID          string
	WorkspaceID string
	EntityID    string
	Predicate   string
	Value       string
	Confidence  float64
	Source      string
	CreatedAt   time.Time
}

// EntityQuery specifies filters for listing entities.
type EntityQuery struct {
	Type       string
	NamePrefix string
	Limit      int
}

// FactQuery specifies filters for listing facts.
type FactQuery struct {
	EntityID  string
	Predicate string
	Limit     int
}

// RelOpts specifies filters for listing relationships from an entity.
type RelOpts struct {
	Type      string
	Direction string // "outgoing", "incoming", "both"
	Limit     int
}

// TraversalFilter constrains graph traversal operations.
type TraversalFilter struct {
	RelationshipTypes []string
	MaxDepth          int
}

// Graph represents a subgraph of entities and their relationships.
type Graph struct {
	Entities      []*Entity
	Relationships []*Relationship
}

// --- Vector types ---

// VectorResult represents a single result from a vector similarity search.
type VectorResult struct {
	ID       string
	Score    float64 // Distance metric: lower = more similar; 0.0 = exact match.
	Metadata map[string]any
}

// --- Gateway types ---

// User represents a human user of the system.
type User struct {
	ID         string
	Name       string
	Role       string
	Identities []UserIdentity
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UserIdentity links a user to a messaging platform account.
// Fields match the proto UserIdentity message (common.v1.UserIdentity).
type UserIdentity struct {
	UserID         string
	Platform       string
	PlatformUserID string
	DisplayName    string
}

// Pairing represents a binding between a user, channel, and workspace.
type Pairing struct {
	ID          string
	UserID      string
	ChannelType string
	ChannelID   string
	WorkspaceID string
	Status      PairingStatus
	CreatedAt   time.Time
}

// PairingStatus represents the approval state of a channel pairing.
type PairingStatus string

const (
	PairingStatusActive  PairingStatus = "active"
	PairingStatusPending PairingStatus = "pending"
	PairingStatusDenied  PairingStatus = "denied"
)

// AuditEntry records a security-relevant action in the system.
type AuditEntry struct {
	ID          string
	Timestamp   time.Time
	Action      string
	Actor       string
	Plugin      string
	WorkspaceID string
	SessionID   string
	Details     map[string]any
	Result      string
}

// AuditFilter specifies criteria for querying audit entries.
type AuditFilter struct {
	Action      string
	Actor       string
	Plugin      string
	WorkspaceID string
	From        time.Time
	To          time.Time
	Limit       int
	Offset      int
}

// --- Query options ---

// ListOpts provides pagination parameters for list operations.
type ListOpts struct {
	Limit  int
	Offset int
}

// SearchOpts provides pagination parameters for search operations.
type SearchOpts struct {
	Limit  int
	Offset int
}

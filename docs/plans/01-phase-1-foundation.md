# Phase 1: Foundation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Establish the foundational layers — proto definitions, storage interfaces, SQLite implementations, config management, and plugin SDK types.

**Architecture:** Bottom-up: proto definitions first (they generate Go types), then storage interfaces (pure Go interfaces), then SQLite implementations, then the factory that wires them together. Config management and plugin SDK types are independent tracks.

**Tech Stack:** buf (protobuf), mattn/go-sqlite3, asg017/sqlite-vec (CGO_ENABLED=1), spf13/viper, testify

**Design Docs:**

- [Section 1: Core Architecture](../design/01-core-architecture.md) — proto layout, layer model
- [Section 2: Plugin System](../design/02-plugin-system.md) — gRPC contracts
- [Section 11: Storage Interfaces](../design/11-storage-interfaces.md) — all interfaces, types, factory, SQLite schemas
- [Section 7: Provider System](../design/07-provider-system.md) — provider proto contract
- [Section 4: Channel System](../design/04-channel-system.md) — channel proto contract

---

## Task 1: buf Configuration and Common Proto Types

**Files:**

- Create: `buf.yaml`
- Create: `buf.gen.yaml`
- Create: `api/proto/common/v1/types.proto`

**Step 1: Write buf configuration**

Create `buf.yaml` at project root:

```yaml
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors

version: v2
modules:
  - path: api/proto
lint:
  use:
    - DEFAULT
breaking:
  use:
    - FILE
```

Create `buf.gen.yaml` at project root:

```yaml
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors

version: v2
plugins:
  - remote: buf.build/protocolbuffers/go
    out: internal/gen/proto
    opt:
      - paths=source_relative
  - remote: buf.build/grpc/go
    out: internal/gen/proto
    opt:
      - paths=source_relative
```

**Step 2: Define common types proto**

Create `api/proto/common/v1/types.proto` with shared message types used across all services:

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package common.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/common/v1;commonv1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";

// Message represents a conversation message.
message Message {
  string id = 1;
  string session_id = 2;
  Role role = 3;
  string content = 4;
  string tool_call_id = 5;
  string tool_name = 6;
  google.protobuf.Timestamp created_at = 7;
  map<string, string> metadata = 8;
}

enum Role {
  ROLE_UNSPECIFIED = 0;
  ROLE_USER = 1;
  ROLE_ASSISTANT = 2;
  ROLE_SYSTEM = 3;
  ROLE_TOOL = 4;
}

// ToolDefinition describes a tool available to the agent.
message ToolDefinition {
  string name = 1;
  string description = 2;
  google.protobuf.Struct input_schema = 3;
}

// ToolCall represents a tool invocation by the LLM.
message ToolCall {
  string id = 1;
  string name = 2;
  string arguments = 3;  // JSON string
}

// UserIdentity maps a platform user to a canonical identity.
message UserIdentity {
  string user_id = 1;
  string platform = 2;
  string platform_user_id = 3;
  string display_name = 4;
}

// ChannelCapabilities declares what a channel supports.
message ChannelCapabilities {
  bool supports_media = 1;
  bool supports_reactions = 2;
  bool supports_threads = 3;
  bool supports_editing = 4;
  bool supports_typing = 5;
  bool supports_voice = 6;
  bool supports_rich_text = 7;
  int32 max_message_length = 8;
  repeated string media_types = 9;
}

// ModelCapabilities declares what a model supports.
message ModelCapabilities {
  bool supports_tools = 1;
  bool supports_vision = 2;
  bool supports_streaming = 3;
  bool supports_thinking = 4;
  int32 max_context_tokens = 5;
  int32 max_output_tokens = 6;
}

// Usage tracks token consumption for a single LLM call.
message Usage {
  int32 input_tokens = 1;
  int32 output_tokens = 2;
  int32 cache_read_tokens = 3;
  int32 cache_write_tokens = 4;
}
```

**Step 3: Generate and verify**

Run: `task proto`

Expected: `internal/gen/proto/common/v1/types.pb.go` is generated with no errors.

**Step 4: Commit**

```bash
git add buf.yaml buf.gen.yaml api/proto/common/v1/types.proto internal/gen/proto/
git commit -m "feat(proto): add buf config and common types"
```

---

## Task 2: Plugin Service Proto Definitions

**Files:**

- Create: `api/proto/plugin/v1/lifecycle.proto`
- Create: `api/proto/plugin/v1/channel.proto`
- Create: `api/proto/plugin/v1/tool.proto`
- Create: `api/proto/plugin/v1/provider.proto`

**Step 1: Define plugin lifecycle service**

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package plugin.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/plugin/v1;pluginv1";

import "google/protobuf/struct.proto";

// PluginLifecycle is implemented by all plugins.
service PluginLifecycle {
  rpc Init(InitRequest) returns (InitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
}

message InitRequest {
  google.protobuf.Struct config = 1;
}

message InitResponse {
  bool ok = 1;
  string error = 2;
}

message HealthRequest {}

message HealthResponse {
  HealthStatus status = 1;
  string message = 2;
}

enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_DEGRADED = 2;
  HEALTH_STATUS_UNHEALTHY = 3;
}

message ShutdownRequest {
  int32 timeout_seconds = 1;
}

message ShutdownResponse {
  bool clean = 1;
}
```

**Step 2: Define channel service**

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package plugin.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/plugin/v1;pluginv1";

import "common/v1/types.proto";
import "google/protobuf/timestamp.proto";

service Channel {
  rpc Start(StartRequest) returns (stream InboundMessage);
  rpc Send(SendRequest) returns (SendResponse);
  rpc UpdatePresence(PresenceRequest) returns (PresenceResponse);
  rpc GetIdentity(GetIdentityRequest) returns (common.v1.UserIdentity);
}

message StartRequest {}

message InboundMessage {
  string message_id = 1;
  string channel_id = 2;
  common.v1.UserIdentity sender = 3;
  string content = 4;
  string thread_id = 5;
  repeated MediaAttachment media = 6;
  google.protobuf.Timestamp timestamp = 7;
  map<string, string> metadata = 8;
}

message MediaAttachment {
  string url = 1;
  string mime_type = 2;
  string filename = 3;
  int64 size_bytes = 4;
}

message SendRequest {
  string channel_id = 1;
  string content = 2;
  string thread_id = 3;
  repeated MediaAttachment media = 4;
  bool typing_indicator = 5;
  string reply_to_message_id = 6;
}

message SendResponse {
  bool ok = 1;
  string platform_message_id = 2;
  string error = 3;
}

message PresenceRequest {
  string channel_id = 1;
  PresenceStatus status = 2;
}

enum PresenceStatus {
  PRESENCE_STATUS_UNSPECIFIED = 0;
  PRESENCE_STATUS_ONLINE = 1;
  PRESENCE_STATUS_TYPING = 2;
  PRESENCE_STATUS_OFFLINE = 3;
}

message PresenceResponse {
  bool ok = 1;
}

message GetIdentityRequest {
  string platform_user_id = 1;
}
```

**Step 3: Define tool service**

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package plugin.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/plugin/v1;pluginv1";

import "common/v1/types.proto";
import "google/protobuf/struct.proto";

service Tool {
  rpc Describe(DescribeRequest) returns (DescribeResponse);
  rpc Execute(ExecuteRequest) returns (stream ExecuteChunk);
}

message DescribeRequest {}

message DescribeResponse {
  repeated common.v1.ToolDefinition tools = 1;
}

message ExecuteRequest {
  string tool_name = 1;
  string arguments = 2;  // JSON string
  string session_id = 3;
  int32 timeout_seconds = 4;
}

message ExecuteChunk {
  oneof chunk {
    string text = 1;
    string error = 2;
    bool done = 3;
  }
}
```

**Step 4: Define provider service**

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package plugin.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/plugin/v1;pluginv1";

import "common/v1/types.proto";
import "google/protobuf/struct.proto";

service Provider {
  rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
  rpc Chat(ChatRequest) returns (stream ChatEvent);
  rpc Status(StatusRequest) returns (StatusResponse);
}

message ListModelsRequest {}

message ListModelsResponse {
  repeated ModelInfo models = 1;
}

message ModelInfo {
  string id = 1;
  string name = 2;
  string provider = 3;
  common.v1.ModelCapabilities capabilities = 4;
}

message ChatRequest {
  string model = 1;
  repeated common.v1.Message messages = 2;
  repeated common.v1.ToolDefinition tools = 3;
  string system_prompt = 4;
  ChatOptions options = 5;
}

message ChatOptions {
  float temperature = 1;
  int32 max_tokens = 2;
  repeated string stop_sequences = 3;
  bool stream = 4;
}

message ChatEvent {
  oneof event {
    TextDelta text_delta = 1;
    common.v1.ToolCall tool_call = 2;
    common.v1.Usage usage = 3;
    bool done = 4;
    string error = 5;
  }
}

message TextDelta {
  string text = 1;
}

message StatusRequest {}

message StatusResponse {
  bool available = 1;
  string provider = 2;
  string message = 3;
}
```

**Step 5: Generate and verify**

Run: `task proto`

Expected: All `*.pb.go` and `*_grpc.pb.go` files generated in `internal/gen/proto/plugin/v1/` with no errors.

**Step 6: Commit**

```bash
git add api/proto/plugin/v1/ internal/gen/proto/
git commit -m "feat(proto): add plugin service definitions (lifecycle, channel, tool, provider)"
```

---

## Task 3: Storage Domain Types

**Files:**

- Create: `internal/store/types.go`

**Step 1: Write the test**

Create `internal/store/types_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
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
```

**Step 2: Run test to verify it fails**

Run: `task test`

Expected: FAIL — `store` package doesn't exist yet.

**Step 3: Write implementation**

Create `internal/store/types.go` with all domain types from Section 11 + Section 8:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "time"

// --- Session types ---

type SessionStatus string

const (
	SessionStatusActive   SessionStatus = "active"
	SessionStatusPaused   SessionStatus = "paused"
	SessionStatusArchived SessionStatus = "archived"
)

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

type ToolBudget struct {
	MaxCallsPerTurn    int
	MaxCallsPerSession int
	Used               int
}

type TokenBudget struct {
	MaxPerSession int
	MaxPerHour    int
	MaxPerDay     int
	UsedSession   int
	UsedHour      int
	UsedDay       int
}

// --- Message types ---

type MessageRole string

const (
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleSystem    MessageRole = "system"
	MessageRoleTool      MessageRole = "tool"
)

type Message struct {
	ID         string
	SessionID  string
	Role       MessageRole
	Content    string
	ToolCallID string
	ToolName   string
	CreatedAt  time.Time
	Metadata   map[string]string
}

// --- Memory types ---

type Summary struct {
	ID          string
	WorkspaceID string
	FromTime    time.Time
	ToTime      time.Time
	Content     string
	MessageIDs  []string
	CreatedAt   time.Time
}

type Entity struct {
	ID          string
	WorkspaceID string
	Type        string
	Name        string
	Properties  map[string]any
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Relationship struct {
	ID       string
	FromID   string
	ToID     string
	Type     string
	Metadata map[string]any
}

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

type EntityQuery struct {
	Type       string
	NamePrefix string
	Limit      int
}

type FactQuery struct {
	EntityID  string
	Predicate string
	Limit     int
}

type RelOpts struct {
	Type      string
	Direction string // "outgoing", "incoming", "both"
	Limit     int
}

type TraversalFilter struct {
	RelationshipTypes []string
	MaxDepth          int
}

type Graph struct {
	Entities      []*Entity
	Relationships []*Relationship
}

// --- Vector types ---

type VectorResult struct {
	ID       string
	Score    float64
	Metadata map[string]any
}

// --- Gateway types ---

type User struct {
	ID          string
	Name        string
	Role        string
	Identities  []UserIdentity
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserIdentity struct {
	Channel    string
	PlatformID string
}

type Pairing struct {
	ID          string
	UserID      string
	ChannelType string
	ChannelID   string
	WorkspaceID string
	Status      PairingStatus
	CreatedAt   time.Time
}

type PairingStatus string

const (
	PairingStatusActive  PairingStatus = "active"
	PairingStatusPending PairingStatus = "pending"
	PairingStatusDenied  PairingStatus = "denied"
)

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

type ListOpts struct {
	Limit  int
	Offset int
}

type SearchOpts struct {
	Limit  int
	Offset int
}
```

**Step 4: Run test to verify it passes**

Run: `task test`

Expected: All type tests PASS.

**Step 5: Commit**

```bash
git add internal/store/types.go internal/store/types_test.go
git commit -m "feat(store): add storage domain types"
```

---

## Task 4: Storage Interfaces

**Files:**

- Create: `internal/store/store.go` — SessionStore, top-level
- Create: `internal/store/memory.go` — MemoryStore, MessageStore, SummaryStore, KnowledgeStore
- Create: `internal/store/gateway.go` — GatewayStore, UserStore, PairingStore, AuditStore
- Create: `internal/store/vector.go` — VectorStore

**Step 1: Write interface compilation tests**

Create `internal/store/interfaces_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
)

// Compile-time interface satisfaction checks.
// These ensure the interfaces are well-defined and importable.
// Actual implementation tests are in the sqlite/ package.

func TestSessionStoreInterfaceExists(t *testing.T) {
	var _ store.SessionStore = nil
}

func TestMemoryStoreInterfaceExists(t *testing.T) {
	var _ store.MemoryStore = nil
}

func TestMessageStoreInterfaceExists(t *testing.T) {
	var _ store.MessageStore = nil
}

func TestSummaryStoreInterfaceExists(t *testing.T) {
	var _ store.SummaryStore = nil
}

func TestKnowledgeStoreInterfaceExists(t *testing.T) {
	var _ store.KnowledgeStore = nil
}

func TestVectorStoreInterfaceExists(t *testing.T) {
	var _ store.VectorStore = nil
}

func TestGatewayStoreInterfaceExists(t *testing.T) {
	var _ store.GatewayStore = nil
}

func TestUserStoreInterfaceExists(t *testing.T) {
	var _ store.UserStore = nil
}

func TestPairingStoreInterfaceExists(t *testing.T) {
	var _ store.PairingStore = nil
}

func TestAuditStoreInterfaceExists(t *testing.T) {
	var _ store.AuditStore = nil
}
```

**Step 2: Run test to verify it fails**

Run: `task test`

Expected: FAIL — interfaces not defined yet.

**Step 3: Write the interfaces**

`internal/store/store.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// SessionStore manages conversation sessions and the active message window.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	ListSessions(ctx context.Context, workspaceID string, opts ListOpts) ([]*Session, error)
	DeleteSession(ctx context.Context, id string) error

	// Active message window (last N messages in LLM context).
	AppendMessage(ctx context.Context, sessionID string, msg *Message) error
	GetActiveWindow(ctx context.Context, sessionID string, limit int) ([]*Message, error)
}
```

`internal/store/memory.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import (
	"context"
	"time"
)

// MemoryStore groups the three non-vector memory subsystems.
// Sub-interfaces are independently swappable via config.
type MemoryStore interface {
	Messages() MessageStore
	Summaries() SummaryStore
	Knowledge() KnowledgeStore
	Close() error
}

// MessageStore manages Tier 1: recent searchable messages (FTS5).
type MessageStore interface {
	Append(ctx context.Context, workspaceID string, msg *Message) error
	Search(ctx context.Context, workspaceID string, query string, opts SearchOpts) ([]*Message, error)
	GetRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Message, error)
	Count(ctx context.Context, workspaceID string) (int64, error)
	Trim(ctx context.Context, workspaceID string, keepLast int) (int64, error)
	Close() error
}

// SummaryStore manages Tier 2: LLM-generated compaction summaries.
type SummaryStore interface {
	Store(ctx context.Context, workspaceID string, summary *Summary) error
	GetByRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Summary, error)
	GetLatest(ctx context.Context, workspaceID string, n int) ([]*Summary, error)
	Close() error
}

// KnowledgeStore manages Tier 3: entities, facts, and relationships.
type KnowledgeStore interface {
	PutEntity(ctx context.Context, workspaceID string, entity *Entity) error
	GetEntity(ctx context.Context, workspaceID string, id string) (*Entity, error)
	FindEntities(ctx context.Context, workspaceID string, query EntityQuery) ([]*Entity, error)

	PutRelationship(ctx context.Context, rel *Relationship) error
	GetRelationships(ctx context.Context, entityID string, opts RelOpts) ([]*Relationship, error)

	PutFact(ctx context.Context, workspaceID string, fact *Fact) error
	FindFacts(ctx context.Context, workspaceID string, query FactQuery) ([]*Fact, error)

	Traverse(ctx context.Context, startID string, depth int, filter TraversalFilter) (*Graph, error)

	Close() error
}
```

`internal/store/vector.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// VectorStore manages Tier 4: embedding storage and semantic search.
type VectorStore interface {
	Store(ctx context.Context, id string, embedding []float32, metadata map[string]any) error
	Search(ctx context.Context, query []float32, k int, filters map[string]any) ([]VectorResult, error)
	Delete(ctx context.Context, ids []string) error
	Close() error
}
```

`internal/store/gateway.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// GatewayStore manages global (non-workspace) state.
type GatewayStore interface {
	Users() UserStore
	Pairings() PairingStore
	AuditLog() AuditStore
	Close() error
}

// UserStore manages user accounts.
type UserStore interface {
	Create(ctx context.Context, user *User) error
	Get(ctx context.Context, id string) (*User, error)
	GetByExternalID(ctx context.Context, provider, externalID string) (*User, error)
	Update(ctx context.Context, user *User) error
	List(ctx context.Context, opts ListOpts) ([]*User, error)
	Delete(ctx context.Context, id string) error
}

// PairingStore manages channel-user-workspace bindings.
type PairingStore interface {
	Create(ctx context.Context, pairing *Pairing) error
	GetByChannel(ctx context.Context, channelType, channelID string) (*Pairing, error)
	GetByUser(ctx context.Context, userID string) ([]*Pairing, error)
	Delete(ctx context.Context, id string) error
}

// AuditStore manages the audit log.
type AuditStore interface {
	Append(ctx context.Context, entry *AuditEntry) error
	Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
}
```

**Step 4: Run test to verify it passes**

Run: `task test`

Expected: All interface compilation tests PASS.

**Step 5: Commit**

```bash
git add internal/store/store.go internal/store/memory.go internal/store/vector.go internal/store/gateway.go internal/store/interfaces_test.go
git commit -m "feat(store): add storage interfaces (SessionStore, MemoryStore, VectorStore, GatewayStore)"
```

---

## Task 5: SQLite SessionStore Implementation

**Files:**

- Create: `internal/store/sqlite/session.go`
- Create: `internal/store/sqlite/session_test.go`
- Create: `internal/store/sqlite/testhelper_test.go` — shared test utilities

**Step 1: Write test helper**

Create `internal/store/sqlite/testhelper_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// testDir creates a temp directory for a test and returns cleanup func.
func testDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sigil-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// testDBPath returns a temp SQLite database path.
func testDBPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(testDir(t), name+".db")
}
```

**Step 2: Write failing tests**

Create `internal/store/sqlite/session_test.go` with table-driven tests:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore_CRUD(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	session := &store.Session{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   time.Now().Truncate(time.Millisecond),
		UpdatedAt:   time.Now().Truncate(time.Millisecond),
	}

	// Create
	err = ss.CreateSession(ctx, session)
	require.NoError(t, err)

	// Get
	got, err := ss.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.WorkspaceID, got.WorkspaceID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, store.SessionStatusActive, got.Status)

	// Update
	session.Status = store.SessionStatusPaused
	session.Summary = "Updated summary"
	err = ss.UpdateSession(ctx, session)
	require.NoError(t, err)

	got, err = ss.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, store.SessionStatusPaused, got.Status)
	assert.Equal(t, "Updated summary", got.Summary)

	// List
	sessions, err := ss.ListSessions(ctx, "ws-1", store.ListOpts{})
	require.NoError(t, err)
	assert.Len(t, sessions, 1)

	// Delete
	err = ss.DeleteSession(ctx, "sess-1")
	require.NoError(t, err)

	_, err = ss.GetSession(ctx, "sess-1")
	assert.Error(t, err)
}

func TestSessionStore_ActiveWindow(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-window")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	// Create session first
	err = ss.CreateSession(ctx, &store.Session{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "usr-1",
		Status:      store.SessionStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	require.NoError(t, err)

	// Append messages
	for i := 0; i < 5; i++ {
		msg := &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		err = ss.AppendMessage(ctx, "sess-1", msg)
		require.NoError(t, err)
	}

	// Get last 3 messages
	msgs, err := ss.GetActiveWindow(ctx, "sess-1", 3)
	require.NoError(t, err)
	assert.Len(t, msgs, 3)
	// Should be most recent messages, ordered chronologically
	assert.Equal(t, "Message 2", msgs[0].Content)
	assert.Equal(t, "Message 4", msgs[2].Content)
}

func TestSessionStore_GetNonExistent(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "sessions-noent")
	ss, err := sqlite.NewSessionStore(db)
	require.NoError(t, err)

	_, err = ss.GetSession(ctx, "nonexistent")
	assert.Error(t, err)
}
```

**Step 3: Run test to verify it fails**

Run: `task test`

Expected: FAIL — `sqlite` package doesn't exist.

**Step 4: Implement SQLite SessionStore**

Create `internal/store/sqlite/session.go` implementing `store.SessionStore` using `mattn/go-sqlite3`. The implementation should:

- Create `sessions` and `messages` tables on init
- Use prepared statements for all operations
- `GetActiveWindow` returns messages ordered by `created_at` with LIMIT, taking the N most recent

**Step 5: Run test to verify it passes**

Run: `task test`

Expected: All SessionStore tests PASS.

**Step 6: Commit**

```bash
git add internal/store/sqlite/
git commit -m "feat(store): add SQLite SessionStore implementation"
```

---

## Task 6: SQLite MessageStore (FTS5) Implementation

**Files:**

- Create: `internal/store/sqlite/message.go`
- Create: `internal/store/sqlite/message_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageStore_AppendAndSearch(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer ms.Close()

	// Append messages
	msgs := []struct {
		id      string
		content string
	}{
		{"msg-1", "The Kubernetes cluster is running smoothly"},
		{"msg-2", "We need to update the Terraform configuration"},
		{"msg-3", "The weather is nice today"},
	}

	for _, m := range msgs {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        m.id,
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   m.content,
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	// Search for Kubernetes
	results, err := ms.Search(ctx, "ws-1", "Kubernetes", store.SearchOpts{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Contains(t, results[0].Content, "Kubernetes")

	// Search for something not present
	results, err = ms.Search(ctx, "ws-1", "Python", store.SearchOpts{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestMessageStore_Count(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-count")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer ms.Close()

	for i := 0; i < 3; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	count, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMessageStore_Trim(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-trim")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer ms.Close()

	for i := 0; i < 10; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		})
		require.NoError(t, err)
	}

	// Trim to keep last 3
	trimmed, err := ms.Trim(ctx, "ws-1", 3)
	require.NoError(t, err)
	assert.Equal(t, int64(7), trimmed)

	count, err := ms.Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMessageStore_GetRange(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "messages-range")
	ms, err := sqlite.NewMessageStore(db)
	require.NoError(t, err)
	defer ms.Close()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		err = ms.Append(ctx, "ws-1", &store.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-1",
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("Message %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		})
		require.NoError(t, err)
	}

	// Get messages in first 3 hours
	from := base
	to := base.Add(3 * time.Hour)
	results, err := ms.GetRange(ctx, "ws-1", from, to)
	require.NoError(t, err)
	assert.Len(t, results, 3) // messages 0, 1, 2
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

Create `internal/store/sqlite/message.go` with:

- A `messages` table (id, workspace_id, session_id, role, content, tool_call_id, tool_name, created_at, metadata)
- A FTS5 virtual table: `CREATE VIRTUAL TABLE messages_fts USING fts5(content, content_rowid='rowid')`
- Triggers to sync inserts/deletes between main table and FTS table
- `Search` uses `messages_fts MATCH ?` with JOIN back to main table

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/sqlite/message.go internal/store/sqlite/message_test.go
git commit -m "feat(store): add SQLite MessageStore with FTS5 search"
```

---

## Task 7: SQLite SummaryStore Implementation

**Files:**

- Create: `internal/store/sqlite/summary.go`
- Create: `internal/store/sqlite/summary_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "summaries")
	ss, err := sqlite.NewSummaryStore(db)
	require.NoError(t, err)
	defer ss.Close()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	summaries := []*store.Summary{
		{ID: "sum-1", WorkspaceID: "ws-1", FromTime: base, ToTime: base.Add(1 * time.Hour), Content: "Discussion about K8s", CreatedAt: base.Add(1 * time.Hour)},
		{ID: "sum-2", WorkspaceID: "ws-1", FromTime: base.Add(1 * time.Hour), ToTime: base.Add(2 * time.Hour), Content: "Terraform planning", CreatedAt: base.Add(2 * time.Hour)},
		{ID: "sum-3", WorkspaceID: "ws-1", FromTime: base.Add(2 * time.Hour), ToTime: base.Add(3 * time.Hour), Content: "Monitoring setup", CreatedAt: base.Add(3 * time.Hour)},
	}

	for _, s := range summaries {
		err = ss.Store(ctx, "ws-1", s)
		require.NoError(t, err)
	}

	// GetByRange
	results, err := ss.GetByRange(ctx, "ws-1", base, base.Add(2*time.Hour))
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// GetLatest
	results, err = ss.GetLatest(ctx, "ws-1", 2)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "Monitoring setup", results[0].Content)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement `internal/store/sqlite/summary.go`**

Simple table: `summaries(id, workspace_id, from_time, to_time, content, message_ids, created_at)`. `message_ids` stored as JSON array text.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/sqlite/summary.go internal/store/sqlite/summary_test.go
git commit -m "feat(store): add SQLite SummaryStore implementation"
```

---

## Task 8: SQLite KnowledgeStore (RDF Triples) Implementation

**Files:**

- Create: `internal/store/sqlite/knowledge.go`
- Create: `internal/store/sqlite/knowledge_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKnowledgeStore_Entities(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer ks.Close()

	entity := &store.Entity{
		ID:          "ent-1",
		WorkspaceID: "ws-1",
		Type:        "person",
		Name:        "Alice",
		Properties:  map[string]any{"role": "engineer"},
		CreatedAt:   time.Now(),
	}

	err = ks.PutEntity(ctx, "ws-1", entity)
	require.NoError(t, err)

	got, err := ks.GetEntity(ctx, "ws-1", "ent-1")
	require.NoError(t, err)
	assert.Equal(t, "Alice", got.Name)
	assert.Equal(t, "person", got.Type)

	// Find by type
	entities, err := ks.FindEntities(ctx, "ws-1", store.EntityQuery{Type: "person"})
	require.NoError(t, err)
	assert.Len(t, entities, 1)
}

func TestKnowledgeStore_Relationships(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-rels")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer ks.Close()

	// Create entities first
	for _, e := range []*store.Entity{
		{ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now()},
		{ID: "bob", WorkspaceID: "ws-1", Type: "person", Name: "Bob", CreatedAt: time.Now()},
	} {
		err = ks.PutEntity(ctx, "ws-1", e)
		require.NoError(t, err)
	}

	rel := &store.Relationship{
		ID:     "rel-1",
		FromID: "alice",
		ToID:   "bob",
		Type:   "works_with",
	}
	err = ks.PutRelationship(ctx, rel)
	require.NoError(t, err)

	rels, err := ks.GetRelationships(ctx, "alice", store.RelOpts{Direction: "outgoing"})
	require.NoError(t, err)
	assert.Len(t, rels, 1)
	assert.Equal(t, "works_with", rels[0].Type)
}

func TestKnowledgeStore_Facts(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-facts")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer ks.Close()

	err = ks.PutEntity(ctx, "ws-1", &store.Entity{
		ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	fact := &store.Fact{
		ID:          "fact-1",
		WorkspaceID: "ws-1",
		EntityID:    "alice",
		Predicate:   "occupation",
		Value:       "software engineer",
		Confidence:  0.95,
		CreatedAt:   time.Now(),
	}
	err = ks.PutFact(ctx, "ws-1", fact)
	require.NoError(t, err)

	facts, err := ks.FindFacts(ctx, "ws-1", store.FactQuery{EntityID: "alice"})
	require.NoError(t, err)
	assert.Len(t, facts, 1)
	assert.Equal(t, "software engineer", facts[0].Value)
}

func TestKnowledgeStore_Traverse(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "knowledge-traverse")
	ks, err := sqlite.NewKnowledgeStore(db)
	require.NoError(t, err)
	defer ks.Close()

	// Build: alice -> bob -> charlie
	entities := []*store.Entity{
		{ID: "alice", WorkspaceID: "ws-1", Type: "person", Name: "Alice", CreatedAt: time.Now()},
		{ID: "bob", WorkspaceID: "ws-1", Type: "person", Name: "Bob", CreatedAt: time.Now()},
		{ID: "charlie", WorkspaceID: "ws-1", Type: "person", Name: "Charlie", CreatedAt: time.Now()},
	}
	for _, e := range entities {
		require.NoError(t, ks.PutEntity(ctx, "ws-1", e))
	}
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r1", FromID: "alice", ToID: "bob", Type: "knows"}))
	require.NoError(t, ks.PutRelationship(ctx, &store.Relationship{ID: "r2", FromID: "bob", ToID: "charlie", Type: "knows"}))

	graph, err := ks.Traverse(ctx, "alice", 2, store.TraversalFilter{})
	require.NoError(t, err)
	assert.Len(t, graph.Entities, 3) // alice, bob, charlie
	assert.Len(t, graph.Relationships, 2)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement using RDF triple model**

Schema per Section 11:

```sql
CREATE TABLE triples (
    subject   TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object    TEXT NOT NULL,
    workspace TEXT NOT NULL,
    metadata  TEXT,
    created   TEXT NOT NULL,
    UNIQUE(workspace, subject, predicate, object)
);
CREATE INDEX idx_spo ON triples(workspace, subject, predicate, object);
CREATE INDEX idx_pos ON triples(workspace, predicate, object, subject);
CREATE INDEX idx_osp ON triples(workspace, object, subject, predicate);
```

Mapping: entities → `(id, "type", type)` + `(id, "name", name)` + property triples. Relationships → `(fromID, relType, toID)`. Facts → `(entityID, predicate, value)`. Traverse → recursive CTE.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/sqlite/knowledge.go internal/store/sqlite/knowledge_test.go
git commit -m "feat(store): add SQLite KnowledgeStore with RDF triples"
```

---

## Task 9: SQLite VectorStore Implementation

**Files:**

- Create: `internal/store/sqlite/vector.go`
- Create: `internal/store/sqlite/vector_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/store/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorStore_StoreAndSearch(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors")
	vs, err := sqlite.NewVectorStore(db, 3) // 3-dimensional embeddings for testing
	require.NoError(t, err)
	defer vs.Close()

	// Store vectors
	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, map[string]any{"source": "test1"})
	require.NoError(t, err)

	err = vs.Store(ctx, "v2", []float32{0.0, 1.0, 0.0}, map[string]any{"source": "test2"})
	require.NoError(t, err)

	err = vs.Store(ctx, "v3", []float32{0.9, 0.1, 0.0}, map[string]any{"source": "test3"})
	require.NoError(t, err)

	// Search for nearest to [1, 0, 0]
	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 2, nil)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "v1", results[0].ID) // exact match should be first
}

func TestVectorStore_Delete(t *testing.T) {
	ctx := context.Background()
	db := testDBPath(t, "vectors-delete")
	vs, err := sqlite.NewVectorStore(db, 3)
	require.NoError(t, err)
	defer vs.Close()

	err = vs.Store(ctx, "v1", []float32{1.0, 0.0, 0.0}, nil)
	require.NoError(t, err)

	err = vs.Delete(ctx, []string{"v1"})
	require.NoError(t, err)

	results, err := vs.Search(ctx, []float32{1.0, 0.0, 0.0}, 10, nil)
	require.NoError(t, err)
	assert.Len(t, results, 0)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement using sqlite-vec**

Uses `asg017/sqlite-vec` extension. Create a virtual table: `CREATE VIRTUAL TABLE vectors USING vec0(id TEXT PRIMARY KEY, embedding float[N])`. Metadata stored in a companion table.

Note: sqlite-vec requires CGO_ENABLED=1, which is already set in Taskfile.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/sqlite/vector.go internal/store/sqlite/vector_test.go
git commit -m "feat(store): add SQLite VectorStore with sqlite-vec"
```

---

## Task 10: SQLite GatewayStore Implementation

**Files:**

- Create: `internal/store/sqlite/gateway.go`
- Create: `internal/store/sqlite/gateway_test.go`

**Step 1: Write failing tests**

Cover UserStore CRUD (create, get, get-by-external-id, update, list, delete), PairingStore (create, get-by-channel, get-by-user, delete), AuditStore (append, query with filters).

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

Three tables: `users`, `user_identities`, `pairings`, `audit_log`. GatewayStore struct composes UserStore, PairingStore, AuditStore implementations.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/sqlite/gateway.go internal/store/sqlite/gateway_test.go
git commit -m "feat(store): add SQLite GatewayStore (users, pairings, audit)"
```

---

## Task 11: Store Factory

**Files:**

- Create: `internal/store/factory.go`
- Create: `internal/store/factory_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWorkspaceStores_SQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "sqlite",
	}

	ss, ms, vs, err := store.NewWorkspaceStores(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, ss)
	assert.NotNil(t, ms)
	assert.NotNil(t, vs)
}

func TestNewGatewayStore_SQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "sqlite",
	}

	gs, err := store.NewGatewayStore(cfg, dir)
	require.NoError(t, err)
	assert.NotNil(t, gs)
}

func TestNewWorkspaceStores_UnknownBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := &store.StorageConfig{
		Backend: "unknown",
	}

	_, _, _, err := store.NewWorkspaceStores(cfg, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement factory**

Add `StorageConfig` struct to `internal/store/config.go`. Factory in `internal/store/factory.go` reads config, creates SQLite backends, returns interfaces.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/store/factory.go internal/store/factory_test.go internal/store/config.go
git commit -m "feat(store): add config-driven store factory"
```

---

## Task 12: Config Management (Viper)

**Files:**

- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultValues(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:18789", cfg.Networking.Listen)
	assert.Equal(t, "local", cfg.Networking.Mode)
	assert.Equal(t, "sqlite", cfg.Storage.Backend)
	assert.Equal(t, 20, cfg.Sessions.Memory.ActiveWindow)
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sigil.yaml")

	content := `
networking:
  listen: "0.0.0.0:9999"
models:
  default: "openai/gpt-4.1"
`
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9999", cfg.Networking.Listen)
	assert.Equal(t, "openai/gpt-4.1", cfg.Models.Default)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("SIGIL_NETWORKING_LISTEN", "10.0.0.1:8080")

	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:8080", cfg.Networking.Listen)
}

func TestValidate_MissingProvider(t *testing.T) {
	cfg := &config.Config{
		Models: config.ModelsConfig{
			Default: "anthropic/claude-sonnet-4-5",
		},
		Providers: map[string]config.ProviderConfig{},
	}

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

Create `internal/config/config.go` with:

- `Config` struct matching `sigil.yaml.example` structure
- `Load(path string) (*Config, error)` using Viper
- `Validate() []error` method for config validation
- Default values matching the example config
- Environment variable prefix: `SIGIL_`

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): add Viper config management with defaults and validation"
```

---

## Task 13: Provider Interface Definitions

**Files:**

- Create: `internal/provider/provider.go`
- Create: `internal/provider/provider_test.go`

**Step 1: Write interface compilation tests**

Create `internal/provider/provider_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
)

// Compile-time interface satisfaction checks.
// These ensure the interfaces are well-defined and importable.
// Actual implementation tests are in the specific provider packages.

func TestProviderInterfaceExists(t *testing.T) {
	var _ provider.Provider = nil
}

func TestRouterInterfaceExists(t *testing.T) {
	var _ provider.Router = nil
}

func TestChatRequestFields(t *testing.T) {
	req := provider.ChatRequest{
		Model:    "claude-sonnet-4-5",
		Messages: []provider.Message{},
	}
	if req.Model == "" {
		t.Fatal("ChatRequest.Model should be settable")
	}
}

func TestChatEventTypes(t *testing.T) {
	// Verify event types compile
	_ = provider.ChatEvent{
		Type: provider.EventTypeTextDelta,
		Text: "test",
	}
	_ = provider.ChatEvent{
		Type: provider.EventTypeToolCall,
	}
	_ = provider.ChatEvent{
		Type: provider.EventTypeDone,
	}
}
```

**Step 2: Run test to verify it fails**

Run: `task test`

Expected: FAIL — `provider` package doesn't exist yet.

**Step 3: Define provider interfaces**

Create `internal/provider/provider.go` with minimal types based on Section 7:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
)

// Provider is the core interface for LLM providers.
// Built-in providers (Anthropic, OpenAI, Google) are compiled into the gateway.
// Plugin providers implement this via gRPC (defined in api/proto/plugin/v1/provider.proto).
type Provider interface {
	// Name returns the provider's name (e.g., "anthropic", "openai").
	Name() string

	// Available checks if the provider is currently available.
	Available(ctx context.Context) bool

	// ListModels returns available models from this provider.
	ListModels(ctx context.Context) ([]ModelInfo, error)

	// Chat sends a chat request and streams responses.
	Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error)

	// Status checks if the provider is available.
	Status(ctx context.Context) (ProviderStatus, error)

	// Close cleans up provider resources.
	Close() error
}

// Router routes chat requests to the appropriate provider based on model name.
// Implements failover logic, budget checks, and workspace overrides.
type Router interface {
	// Route selects a provider for the given model name.
	// Returns the provider and resolved model ID.
	Route(ctx context.Context, workspaceID, modelName string) (Provider, string, error)

	// RegisterProvider adds a provider to the router.
	RegisterProvider(name string, provider Provider) error

	// Close shuts down all registered providers.
	Close() error
}

// ChatRequest represents a request to the LLM.
type ChatRequest struct {
	Model        string
	Messages     []Message
	Tools        []ToolDefinition
	SystemPrompt string
	Options      ChatOptions
}

// ChatOptions contains model configuration.
type ChatOptions struct {
	Temperature    float32
	MaxTokens      int
	StopSequences  []string
	Stream         bool
}

// Message represents a conversation message.
type Message struct {
	Role       MessageRole
	Content    string
	ToolCallID string
	ToolName   string
}

// MessageRole defines the role of a message sender.
type MessageRole string

const (
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleSystem    MessageRole = "system"
	MessageRoleTool      MessageRole = "tool"
)

// ToolDefinition describes a tool available to the agent.
type ToolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ChatEvent is a streaming response event.
type ChatEvent struct {
	Type     EventType
	Text     string
	ToolCall *ToolCall
	Usage    *Usage
	Error    string
}

// EventType defines the type of chat event.
type EventType string

const (
	EventTypeTextDelta EventType = "text_delta"
	EventTypeToolCall  EventType = "tool_call"
	EventTypeUsage     EventType = "usage"
	EventTypeDone      EventType = "done"
	EventTypeError     EventType = "error"
)

// ToolCall represents a tool invocation by the LLM.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string // JSON
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
}

// ModelInfo describes a model's capabilities.
type ModelInfo struct {
	ID           string
	Name         string
	Provider     string
	Capabilities ModelCapabilities
}

// ModelCapabilities declares what a model supports.
type ModelCapabilities struct {
	SupportsTools     bool
	SupportsVision    bool
	SupportsStreaming bool
	SupportsThinking  bool
	MaxContextTokens  int
	MaxOutputTokens   int
}

// ProviderStatus indicates provider health.
type ProviderStatus struct {
	Available bool
	Provider  string
	Message   string
}
```

**Step 4: Run test to verify it passes**

Run: `task test`

Expected: All provider interface compilation tests PASS.

**Step 5: Commit**

```bash
git add internal/provider/
git commit -m "feat(provider): add provider interface definitions"
```

---

## Task 14: Plugin SDK Types

**Files:**

- Create: `pkg/plugin/types.go`
- Create: `pkg/plugin/types_test.go`

**Step 1: Write importability test**

Create `pkg/plugin/types_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestPluginTypeValues(t *testing.T) {
	assert.Equal(t, plugin.PluginType("provider"), plugin.PluginTypeProvider)
	assert.Equal(t, plugin.PluginType("channel"), plugin.PluginTypeChannel)
	assert.Equal(t, plugin.PluginType("tool"), plugin.PluginTypeTool)
	assert.Equal(t, plugin.PluginType("skill"), plugin.PluginTypeSkill)
}

func TestExecutionTierValues(t *testing.T) {
	assert.Equal(t, plugin.ExecutionTier("wasm"), plugin.ExecutionTierWasm)
	assert.Equal(t, plugin.ExecutionTier("process"), plugin.ExecutionTierProcess)
	assert.Equal(t, plugin.ExecutionTier("container"), plugin.ExecutionTierContainer)
}

func TestManifestFields(t *testing.T) {
	manifest := plugin.Manifest{
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    plugin.PluginTypeChannel,
		Execution: plugin.ExecutionConfig{
			Tier: plugin.ExecutionTierProcess,
		},
		Capabilities: []plugin.Capability{
			{Pattern: "channel:send"},
		},
	}
	assert.Equal(t, "test-plugin", manifest.Name)
	assert.Equal(t, plugin.PluginTypeChannel, manifest.Type)
	assert.Len(t, manifest.Capabilities, 1)
}

func TestCapabilityPattern(t *testing.T) {
	cap := plugin.Capability{
		Pattern:     "sessions.read",
		Description: "Read session data",
	}
	assert.Equal(t, "sessions.read", cap.Pattern)
}
```

**Step 2: Run test to verify it fails**

Run: `task test`

Expected: FAIL — `pkg/plugin` package doesn't exist yet.

**Step 3: Define SDK types**

Create `pkg/plugin/types.go` with public types from Section 2:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package plugin provides public types for plugin authors.
// These types define the plugin manifest structure and execution configuration.
package plugin

// PluginType identifies the category of plugin.
type PluginType string

const (
	PluginTypeProvider PluginType = "provider"
	PluginTypeChannel  PluginType = "channel"
	PluginTypeTool     PluginType = "tool"
	PluginTypeSkill    PluginType = "skill"
)

// ExecutionTier determines the isolation level for a plugin.
type ExecutionTier string

const (
	ExecutionTierWasm      ExecutionTier = "wasm"
	ExecutionTierProcess   ExecutionTier = "process"
	ExecutionTierContainer ExecutionTier = "container"
)

// Manifest describes a plugin's metadata, capabilities, and execution requirements.
// This is loaded from plugin.yaml in the plugin directory.
type Manifest struct {
	Name              string                 `yaml:"name"`
	Version           string                 `yaml:"version"`
	Type              PluginType             `yaml:"type"`
	Engine            string                 `yaml:"engine"`
	License           string                 `yaml:"license,omitempty"`
	Capabilities      []Capability           `yaml:"capabilities"`
	DenyCapabilities  []Capability           `yaml:"deny_capabilities,omitempty"`
	Execution         ExecutionConfig        `yaml:"execution"`
	ConfigSchema      map[string]interface{} `yaml:"config_schema,omitempty"`
	Dependencies      map[string]string      `yaml:"dependencies,omitempty"`
	Lifecycle         LifecycleConfig        `yaml:"lifecycle,omitempty"`
	Storage           StorageConfig          `yaml:"storage,omitempty"`
}

// Capability represents a permission pattern.
type Capability struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description,omitempty"`
}

// ExecutionConfig defines how the plugin should be executed.
type ExecutionConfig struct {
	Tier    ExecutionTier  `yaml:"tier"`
	Sandbox SandboxConfig  `yaml:"sandbox,omitempty"`
	Image   string         `yaml:"image,omitempty"`
	Network string         `yaml:"network,omitempty"`
	Memory  string         `yaml:"memory_limit,omitempty"`
}

// SandboxConfig defines sandbox restrictions for process-tier plugins.
type SandboxConfig struct {
	Filesystem FilesystemConfig `yaml:"filesystem,omitempty"`
	Network    NetworkConfig    `yaml:"network,omitempty"`
}

// FilesystemConfig defines filesystem access rules.
type FilesystemConfig struct {
	WriteAllow []string `yaml:"write_allow,omitempty"`
	ReadDeny   []string `yaml:"read_deny,omitempty"`
}

// NetworkConfig defines network access rules.
type NetworkConfig struct {
	Allow []string `yaml:"allow,omitempty"`
	Proxy bool     `yaml:"proxy,omitempty"`
}

// LifecycleConfig defines plugin lifecycle behavior.
type LifecycleConfig struct {
	HotReload              bool   `yaml:"hot_reload,omitempty"`
	GracefulShutdownTimeout string `yaml:"graceful_shutdown_timeout,omitempty"`
}

// StorageConfig defines plugin storage requirements.
type StorageConfig struct {
	KV      bool              `yaml:"kv,omitempty"`
	Volumes []VolumeConfig    `yaml:"volumes,omitempty"`
	Memory  MemoryConfig      `yaml:"memory,omitempty"`
}

// VolumeConfig defines a persistent volume for a plugin.
type VolumeConfig struct {
	Name      string `yaml:"name"`
	Mount     string `yaml:"mount"`
	SizeLimit string `yaml:"size_limit,omitempty"`
	Persist   bool   `yaml:"persist,omitempty"`
}

// MemoryConfig defines memory storage collections.
type MemoryConfig struct {
	Collections []CollectionConfig `yaml:"collections,omitempty"`
}

// CollectionConfig defines a memory collection.
type CollectionConfig struct {
	Name           string `yaml:"name"`
	EmbeddingModel string `yaml:"embedding_model,omitempty"`
	MaxEntries     int    `yaml:"max_entries,omitempty"`
}
```

**Step 4: Run test to verify it passes**

Run: `task test`

Expected: All plugin SDK type tests PASS.

**Step 5: Commit**

```bash
git add pkg/plugin/
git commit -m "feat(plugin): add public SDK types for plugin authors"
```

---

## Gate 1 Checklist

After completing all 14 tasks, verify:

- [ ] `task proto` — generates all proto code without errors
- [ ] `task test` — all tests pass
- [ ] `task lint` — zero lint errors
- [ ] All interfaces in `internal/store/` are defined
- [ ] All SQLite implementations in `internal/store/sqlite/` satisfy interfaces
- [ ] Factory creates correct backends
- [ ] Config loads from file, env vars, and defaults
- [ ] Provider interfaces compile and are importable from `internal/provider/`
- [ ] Plugin SDK types compile and are importable from `pkg/plugin/`

Only proceed to Phase 2 after all checks pass.

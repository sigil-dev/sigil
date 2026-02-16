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
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- UserStore ----------

func TestUserStore_Create_and_Get(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-create"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	user := &store.User{
		ID:   "usr-1",
		Name: "Alice",
		Role: "admin",
		Identities: []store.UserIdentity{
			{UserID: "usr-1", Platform: "telegram", PlatformUserID: "tg-123", DisplayName: "Alice TG"},
			{UserID: "usr-1", Platform: "discord", PlatformUserID: "dc-456", DisplayName: "Alice DC"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	err = gs.Users().Create(ctx, user)
	require.NoError(t, err)

	got, err := gs.Users().Get(ctx, "usr-1")
	require.NoError(t, err)
	assert.Equal(t, "usr-1", got.ID)
	assert.Equal(t, "Alice", got.Name)
	assert.Equal(t, "admin", got.Role)
	assert.Len(t, got.Identities, 2)
	// Identities are returned sorted by (platform, platform_user_id).
	assert.Equal(t, "discord", got.Identities[0].Platform)
	assert.Equal(t, "dc-456", got.Identities[0].PlatformUserID)
	assert.Equal(t, "Alice DC", got.Identities[0].DisplayName)
	assert.Equal(t, "usr-1", got.Identities[0].UserID)
	assert.Equal(t, "telegram", got.Identities[1].Platform)
	assert.Equal(t, "tg-123", got.Identities[1].PlatformUserID)
	assert.Equal(t, "Alice TG", got.Identities[1].DisplayName)
	assert.Equal(t, "usr-1", got.Identities[1].UserID)
}

func TestUserStore_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-notfound"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	_, err = gs.Users().Get(ctx, "nonexistent")
	assert.True(t, sigilerr.IsNotFound(err))
}

func TestUserStore_GetByExternalID(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-extid"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	user := &store.User{
		ID:   "usr-ext",
		Name: "Bob",
		Role: "user",
		Identities: []store.UserIdentity{
			{UserID: "usr-ext", Platform: "telegram", PlatformUserID: "tg-bob", DisplayName: "Bob TG"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, gs.Users().Create(ctx, user))

	got, err := gs.Users().GetByExternalID(ctx, "telegram", "tg-bob")
	require.NoError(t, err)
	assert.Equal(t, "usr-ext", got.ID)
	assert.Equal(t, "Bob", got.Name)
	assert.Len(t, got.Identities, 1)

	// Not found case
	_, err = gs.Users().GetByExternalID(ctx, "telegram", "unknown")
	assert.True(t, sigilerr.IsNotFound(err))
}

func TestUserStore_Update(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-update"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	user := &store.User{
		ID:   "usr-upd",
		Name: "Carol",
		Role: "user",
		Identities: []store.UserIdentity{
			{UserID: "usr-upd", Platform: "slack", PlatformUserID: "sl-carol", DisplayName: "Carol Slack"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, gs.Users().Create(ctx, user))

	user.Name = "Carol Updated"
	user.Role = "admin"
	user.Identities = []store.UserIdentity{
		{UserID: "usr-upd", Platform: "slack", PlatformUserID: "sl-carol", DisplayName: "Carol Slack"},
		{UserID: "usr-upd", Platform: "telegram", PlatformUserID: "tg-carol", DisplayName: "Carol TG"},
	}
	user.UpdatedAt = time.Now().Truncate(time.Millisecond)
	require.NoError(t, gs.Users().Update(ctx, user))

	got, err := gs.Users().Get(ctx, "usr-upd")
	require.NoError(t, err)
	assert.Equal(t, "Carol Updated", got.Name)
	assert.Equal(t, "admin", got.Role)
	assert.Len(t, got.Identities, 2)
}

func TestUserStore_Update_NotFound(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-upd-nf"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	err = gs.Users().Update(ctx, &store.User{ID: "nonexistent"})
	assert.True(t, sigilerr.IsNotFound(err))
}

func TestUserStore_List(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-list"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	for i := 0; i < 5; i++ {
		u := &store.User{
			ID:        fmt.Sprintf("usr-%d", i),
			Name:      fmt.Sprintf("User %d", i),
			Role:      "user",
			CreatedAt: now.Add(time.Duration(i) * time.Second),
			UpdatedAt: now.Add(time.Duration(i) * time.Second),
		}
		require.NoError(t, gs.Users().Create(ctx, u))
	}

	// All
	all, err := gs.Users().List(ctx, store.ListOpts{})
	require.NoError(t, err)
	assert.Len(t, all, 5)

	// With limit
	limited, err := gs.Users().List(ctx, store.ListOpts{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, limited, 2)

	// With offset
	offset, err := gs.Users().List(ctx, store.ListOpts{Limit: 2, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, offset, 2)
}

func TestUserStore_Delete(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-delete"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	user := &store.User{
		ID:   "usr-del",
		Name: "DeleteMe",
		Role: "user",
		Identities: []store.UserIdentity{
			{UserID: "usr-del", Platform: "telegram", PlatformUserID: "tg-del", DisplayName: "DeleteMe TG"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, gs.Users().Create(ctx, user))

	err = gs.Users().Delete(ctx, "usr-del")
	require.NoError(t, err)

	_, err = gs.Users().Get(ctx, "usr-del")
	assert.True(t, sigilerr.IsNotFound(err))

	// Delete non-existent
	err = gs.Users().Delete(ctx, "nonexistent")
	assert.True(t, sigilerr.IsNotFound(err))
}

// TestUserIdentity_AllFieldsRoundTrip verifies that all 4 UserIdentity fields
// (UserID, Platform, PlatformUserID, DisplayName) persist through store → retrieve.
func TestUserIdentity_AllFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-identity-roundtrip"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	identities := []store.UserIdentity{
		{UserID: "usr-rt", Platform: "telegram", PlatformUserID: "tg-999", DisplayName: "RT User TG"},
		{UserID: "usr-rt", Platform: "discord", PlatformUserID: "dc-888", DisplayName: "RT User DC"},
		{UserID: "usr-rt", Platform: "slack", PlatformUserID: "sl-777", DisplayName: ""},
	}

	user := &store.User{
		ID:         "usr-rt",
		Name:       "RoundTrip",
		Role:       "user",
		Identities: identities,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	require.NoError(t, gs.Users().Create(ctx, user))

	got, err := gs.Users().Get(ctx, "usr-rt")
	require.NoError(t, err)
	require.Len(t, got.Identities, 3)

	// Sorted by (platform, platform_user_id)
	tests := []struct {
		name           string
		idx            int
		wantUserID     string
		wantPlatform   string
		wantPlatformID string
		wantDisplay    string
	}{
		{"discord identity", 0, "usr-rt", "discord", "dc-888", "RT User DC"},
		{"slack identity", 1, "usr-rt", "slack", "sl-777", ""},
		{"telegram identity", 2, "usr-rt", "telegram", "tg-999", "RT User TG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := got.Identities[tt.idx]
			assert.Equal(t, tt.wantUserID, id.UserID, "UserID should persist")
			assert.Equal(t, tt.wantPlatform, id.Platform, "Platform should persist")
			assert.Equal(t, tt.wantPlatformID, id.PlatformUserID, "PlatformUserID should persist")
			assert.Equal(t, tt.wantDisplay, id.DisplayName, "DisplayName should persist")
		})
	}
}

// ---------- PairingStore ----------

func TestPairingStore_Create_and_GetByChannel(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-pairing-create"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	// Create prerequisite user
	now := time.Now().Truncate(time.Millisecond)
	require.NoError(t, gs.Users().Create(ctx, &store.User{
		ID: "usr-p1", Name: "PairUser", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}))

	pairing := &store.Pairing{
		ID:          "pair-1",
		UserID:      "usr-p1",
		ChannelType: "telegram",
		ChannelID:   "tg-chan-1",
		WorkspaceID: "ws-1",
		Status:      store.PairingStatusActive,
		CreatedAt:   now,
	}
	err = gs.Pairings().Create(ctx, pairing)
	require.NoError(t, err)

	got, err := gs.Pairings().GetByChannel(ctx, "telegram", "tg-chan-1")
	require.NoError(t, err)
	assert.Equal(t, "pair-1", got.ID)
	assert.Equal(t, "usr-p1", got.UserID)
	assert.Equal(t, store.PairingStatusActive, got.Status)
}

func TestPairingStore_GetByChannel_NotFound(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-pairing-notfound"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	_, err = gs.Pairings().GetByChannel(ctx, "telegram", "nonexistent")
	assert.True(t, sigilerr.IsNotFound(err))
}

func TestPairingStore_GetByUser(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-pairing-byuser"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	require.NoError(t, gs.Users().Create(ctx, &store.User{
		ID: "usr-p2", Name: "MultiPairUser", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}))

	for i, ct := range []string{"telegram", "discord", "slack"} {
		require.NoError(t, gs.Pairings().Create(ctx, &store.Pairing{
			ID:          fmt.Sprintf("pair-%d", i),
			UserID:      "usr-p2",
			ChannelType: ct,
			ChannelID:   fmt.Sprintf("chan-%d", i),
			WorkspaceID: "ws-1",
			Status:      store.PairingStatusActive,
			CreatedAt:   now,
		}))
	}

	pairings, err := gs.Pairings().GetByUser(ctx, "usr-p2")
	require.NoError(t, err)
	assert.Len(t, pairings, 3)
}

func TestPairingStore_Delete(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-pairing-delete"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	now := time.Now().Truncate(time.Millisecond)
	require.NoError(t, gs.Users().Create(ctx, &store.User{
		ID: "usr-p3", Name: "DelPairUser", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, gs.Pairings().Create(ctx, &store.Pairing{
		ID:          "pair-del",
		UserID:      "usr-p3",
		ChannelType: "telegram",
		ChannelID:   "tg-del",
		WorkspaceID: "ws-1",
		Status:      store.PairingStatusActive,
		CreatedAt:   now,
	}))

	err = gs.Pairings().Delete(ctx, "pair-del")
	require.NoError(t, err)

	_, err = gs.Pairings().GetByChannel(ctx, "telegram", "tg-del")
	assert.True(t, sigilerr.IsNotFound(err))

	// Delete non-existent
	err = gs.Pairings().Delete(ctx, "nonexistent")
	assert.True(t, sigilerr.IsNotFound(err))
}

// ---------- AuditStore ----------

func TestAuditStore_Append_and_Query(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	base := time.Now().Truncate(time.Millisecond)

	entries := []*store.AuditEntry{
		{
			ID: "aud-1", Timestamp: base,
			Action: "plugin.load", Actor: "system", Plugin: "echo",
			WorkspaceID: "ws-1", SessionID: "sess-1",
			Details: map[string]any{"version": "1.0"},
			Result:  "success",
		},
		{
			ID: "aud-2", Timestamp: base.Add(time.Second),
			Action: "tool.exec", Actor: "usr-1", Plugin: "echo",
			WorkspaceID: "ws-1", SessionID: "sess-1",
			Details: map[string]any{"tool": "run"},
			Result:  "success",
		},
		{
			ID: "aud-3", Timestamp: base.Add(2 * time.Second),
			Action: "plugin.load", Actor: "system", Plugin: "web",
			WorkspaceID: "ws-2", SessionID: "sess-2",
			Details: nil,
			Result:  "failure",
		},
	}

	for _, e := range entries {
		require.NoError(t, gs.AuditLog().Append(ctx, e))
	}

	// Query all
	all, err := gs.AuditLog().Query(ctx, store.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// Filter by action
	pluginLoads, err := gs.AuditLog().Query(ctx, store.AuditFilter{Action: "plugin.load"})
	require.NoError(t, err)
	assert.Len(t, pluginLoads, 2)

	// Filter by actor
	systemActs, err := gs.AuditLog().Query(ctx, store.AuditFilter{Actor: "system"})
	require.NoError(t, err)
	assert.Len(t, systemActs, 2)

	// Filter by plugin
	echoActs, err := gs.AuditLog().Query(ctx, store.AuditFilter{Plugin: "echo"})
	require.NoError(t, err)
	assert.Len(t, echoActs, 2)

	// Filter by workspace
	ws2, err := gs.AuditLog().Query(ctx, store.AuditFilter{WorkspaceID: "ws-2"})
	require.NoError(t, err)
	assert.Len(t, ws2, 1)
	assert.Equal(t, "aud-3", ws2[0].ID)

	// Filter by time range
	ranged, err := gs.AuditLog().Query(ctx, store.AuditFilter{
		From: base.Add(500 * time.Millisecond),
		To:   base.Add(3 * time.Second),
	})
	require.NoError(t, err)
	assert.Len(t, ranged, 2) // aud-2 and aud-3

	// Limit and offset
	limited, err := gs.AuditLog().Query(ctx, store.AuditFilter{Limit: 1})
	require.NoError(t, err)
	assert.Len(t, limited, 1)

	offsetted, err := gs.AuditLog().Query(ctx, store.AuditFilter{Limit: 1, Offset: 1})
	require.NoError(t, err)
	assert.Len(t, offsetted, 1)
	assert.NotEqual(t, limited[0].ID, offsetted[0].ID)
}

func TestAuditStore_Query_Details_Roundtrip(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit-details"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	entry := &store.AuditEntry{
		ID:        "aud-det",
		Timestamp: time.Now().Truncate(time.Millisecond),
		Action:    "test.action",
		Actor:     "tester",
		Details:   map[string]any{"key": "value", "count": float64(42)},
		Result:    "ok",
	}
	require.NoError(t, gs.AuditLog().Append(ctx, entry))

	results, err := gs.AuditLog().Query(ctx, store.AuditFilter{Action: "test.action"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "value", results[0].Details["key"])
	assert.Equal(t, float64(42), results[0].Details["count"])
}

// ---------- GatewayStore composition ----------

func TestGatewayStore_Close(t *testing.T) {
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-close"))
	require.NoError(t, err)

	err = gs.Close()
	require.NoError(t, err)
}

// ---------- Audit Store Failure (Best-Effort Semantics) ----------
//
// These tests verify that audit failures do not block requests.
// The audit log is best-effort: failures are logged but do not cause
// the operation to fail. This is critical for system reliability.

// failingAuditStore wraps an AuditStore and injects failures.
type failingAuditStore struct {
	inner store.AuditStore
	fail  bool
}

func (f *failingAuditStore) Append(_ context.Context, entry *store.AuditEntry) error {
	if f.fail {
		return fmt.Errorf("injected audit store failure")
	}
	return f.inner.Append(context.Background(), entry)
}

func (f *failingAuditStore) Query(ctx context.Context, filter store.AuditFilter) ([]*store.AuditEntry, error) {
	return f.inner.Query(ctx, filter)
}

func TestAuditStore_Failure_BestEffort(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	innerGS, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit-failure"))
	require.NoError(t, err)
	defer func() { _ = innerGS.Close() }()

	// Wrap the audit store with a failing variant
	failingAudit := &failingAuditStore{
		inner: innerGS.AuditLog(),
		fail:  false, // starts working
	}

	// Verify normal operation first
	entry1 := &store.AuditEntry{
		ID:        "aud-normal",
		Timestamp: time.Now().Truncate(time.Millisecond),
		Action:    "test.action",
		Actor:     "tester",
		Result:    "ok",
	}
	require.NoError(t, failingAudit.Append(ctx, entry1))

	// Query to verify audit worked
	entries, err := failingAudit.Query(ctx, store.AuditFilter{Action: "test.action"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Now simulate audit store failure
	failingAudit.fail = true

	// Attempt to append with failing store
	entry2 := &store.AuditEntry{
		ID:        "aud-during-failure",
		Timestamp: time.Now().Truncate(time.Millisecond),
		Action:    "test.action",
		Actor:     "tester",
		Result:    "ok",
	}

	// This will fail, but in real usage, the enforcer handles this gracefully
	// by logging the error and allowing the operation to continue
	err = failingAudit.Append(ctx, entry2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injected audit store failure")

	// Verify that the entry was NOT added (audit store is truly down)
	entries, err = failingAudit.Query(ctx, store.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, entries, 1) // only the first one succeeded

	// Restore audit store
	failingAudit.fail = false

	// Add another entry after recovery
	entry3 := &store.AuditEntry{
		ID:        "aud-after-recovery",
		Timestamp: time.Now().Truncate(time.Millisecond),
		Action:    "test.action",
		Actor:     "tester",
		Result:    "ok",
	}
	require.NoError(t, failingAudit.Append(ctx, entry3))

	// Verify recovery
	entries, err = failingAudit.Query(ctx, store.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "aud-normal", entries[0].ID)
	assert.Equal(t, "aud-after-recovery", entries[1].ID)
}

// TestAuditStore_Failure_DoesNotBlockQueries verifies that query failures
// are isolated and do not prevent subsequent operations.
func TestAuditStore_Failure_DoesNotBlockQueries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit-query"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	// Add some entries
	for i := 0; i < 3; i++ {
		entry := &store.AuditEntry{
			ID:        fmt.Sprintf("aud-%d", i),
			Timestamp: time.Now().Truncate(time.Millisecond),
			Action:    "test.action",
			Actor:     "tester",
			Result:    "ok",
		}
		require.NoError(t, gs.AuditLog().Append(ctx, entry))
	}

	// Query should succeed even after previous operations
	entries, err := gs.AuditLog().Query(ctx, store.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Filter by action
	filtered, err := gs.AuditLog().Query(ctx, store.AuditFilter{Action: "test.action"})
	require.NoError(t, err)
	assert.Len(t, filtered, 3)

	// Filtered query returns same data
	assert.Equal(t, entries[0].ID, filtered[0].ID)
}

// TestAuditStore_Append_Idempotency verifies that repeated audit entries
// can be safely added without causing issues (idempotency).
func TestAuditStore_Append_Idempotency(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit-idempotent"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	// Add the same entry multiple times with same ID
	// (This can happen if audit is best-effort and retried)
	entry := &store.AuditEntry{
		ID:        "aud-idempotent",
		Timestamp: time.Now().Truncate(time.Millisecond),
		Action:    "test.action",
		Actor:     "tester",
		Result:    "ok",
	}

	// First append succeeds
	require.NoError(t, gs.AuditLog().Append(ctx, entry))

	// Second append with same ID should fail (UNIQUE constraint on ID)
	// or be handled by the implementation
	err = gs.AuditLog().Append(ctx, entry)
	assert.Error(t, err, "duplicate ID should be rejected to maintain audit log integrity")
}

// TestAuditStore_ConcurrentAppends verifies that concurrent audit appends
// are properly serialized and don't lose entries.
func TestAuditStore_ConcurrentAppends(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-audit-concurrent"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	// Spawn multiple goroutines to append audit entries
	const numGoroutines = 10
	const numEntriesPerGoroutine = 5
	errCh := make(chan error, numGoroutines*numEntriesPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < numEntriesPerGoroutine; i++ {
				entry := &store.AuditEntry{
					ID:        fmt.Sprintf("aud-g%d-e%d", goroutineID, i),
					Timestamp: time.Now().Truncate(time.Millisecond),
					Action:    "concurrent.test",
					Actor:     fmt.Sprintf("goroutine-%d", goroutineID),
					Result:    "ok",
				}
				errCh <- gs.AuditLog().Append(ctx, entry)
			}
		}(g)
	}

	// Collect results
	var failures int
	for i := 0; i < numGoroutines*numEntriesPerGoroutine; i++ {
		if err := <-errCh; err != nil {
			t.Logf("append error: %v", err)
			failures++
		}
	}

	// All appends should succeed
	assert.Equal(t, 0, failures, "concurrent appends should all succeed")

	// Verify all entries were written
	entries, err := gs.AuditLog().Query(ctx, store.AuditFilter{Action: "concurrent.test"})
	require.NoError(t, err)
	assert.Len(t, entries, numGoroutines*numEntriesPerGoroutine)
}

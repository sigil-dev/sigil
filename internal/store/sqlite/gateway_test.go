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
			{Channel: "telegram", PlatformID: "tg-123"},
			{Channel: "discord", PlatformID: "dc-456"},
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
	// Identities are returned sorted by (channel, platform_id).
	assert.Equal(t, "discord", got.Identities[0].Channel)
	assert.Equal(t, "dc-456", got.Identities[0].PlatformID)
	assert.Equal(t, "telegram", got.Identities[1].Channel)
	assert.Equal(t, "tg-123", got.Identities[1].PlatformID)
}

func TestUserStore_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	gs, err := sqlite.NewGatewayStore(testDBPath(t, "gw-user-notfound"))
	require.NoError(t, err)
	defer func() { _ = gs.Close() }()

	_, err = gs.Users().Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, store.ErrNotFound)
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
			{Channel: "telegram", PlatformID: "tg-bob"},
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
	assert.ErrorIs(t, err, store.ErrNotFound)
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
			{Channel: "slack", PlatformID: "sl-carol"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, gs.Users().Create(ctx, user))

	user.Name = "Carol Updated"
	user.Role = "admin"
	user.Identities = []store.UserIdentity{
		{Channel: "slack", PlatformID: "sl-carol"},
		{Channel: "telegram", PlatformID: "tg-carol"},
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
	assert.ErrorIs(t, err, store.ErrNotFound)
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
			{Channel: "telegram", PlatformID: "tg-del"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, gs.Users().Create(ctx, user))

	err = gs.Users().Delete(ctx, "usr-del")
	require.NoError(t, err)

	_, err = gs.Users().Get(ctx, "usr-del")
	assert.ErrorIs(t, err, store.ErrNotFound)

	// Delete non-existent
	err = gs.Users().Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, store.ErrNotFound)
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
	assert.ErrorIs(t, err, store.ErrNotFound)
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
	assert.ErrorIs(t, err, store.ErrNotFound)

	// Delete non-existent
	err = gs.Pairings().Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, store.ErrNotFound)
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

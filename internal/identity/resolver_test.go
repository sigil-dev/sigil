// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package identity_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/sigil-dev/sigil/internal/identity"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock UserStore ---

type mockUserStore struct {
	users map[string]*store.User // keyed by "platform:platformUserID"
}

func newMockUserStore(users ...*store.User) *mockUserStore {
	m := &mockUserStore{users: make(map[string]*store.User)}
	for _, u := range users {
		for _, id := range u.Identities {
			key := id.Platform + ":" + id.PlatformUserID
			m.users[key] = u
		}
	}
	return m
}

func (m *mockUserStore) GetByExternalID(_ context.Context, provider, externalID string) (*store.User, error) {
	key := provider + ":" + externalID
	if u, ok := m.users[key]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user not found for %s", key)
}

func (m *mockUserStore) Create(context.Context, *store.User) error                   { return nil }
func (m *mockUserStore) Get(context.Context, string) (*store.User, error)            { return nil, nil }
func (m *mockUserStore) Update(context.Context, *store.User) error                   { return nil }
func (m *mockUserStore) List(context.Context, store.ListOpts) ([]*store.User, error) { return nil, nil }
func (m *mockUserStore) Delete(context.Context, string) error                        { return nil }

// --- Mock PairingStore ---

type mockPairingStore struct{}

func (m *mockPairingStore) Create(context.Context, *store.Pairing) error { return nil }
func (m *mockPairingStore) GetByChannel(context.Context, string, string) (*store.Pairing, error) {
	return nil, nil
}

func (m *mockPairingStore) GetByUser(context.Context, string) ([]*store.Pairing, error) {
	return nil, nil
}
func (m *mockPairingStore) Delete(context.Context, string) error { return nil }

// --- Tests ---

func TestResolver_ResolvePlatformUser(t *testing.T) {
	user := &store.User{
		ID:   "user-1",
		Name: "Alice",
		Role: "member",
		Identities: []store.UserIdentity{
			{UserID: "user-1", Platform: "telegram", PlatformUserID: "tg-alice", DisplayName: "Alice TG"},
			{UserID: "user-1", Platform: "whatsapp", PlatformUserID: "wa-alice", DisplayName: "Alice WA"},
		},
	}

	users := newMockUserStore(user)
	r := identity.NewResolver(users, &mockPairingStore{})
	ctx := context.Background()

	got, err := r.Resolve(ctx, "telegram", "tg-alice")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.ID)
	assert.Equal(t, "Alice", got.Name)

	got2, err := r.Resolve(ctx, "whatsapp", "wa-alice")
	require.NoError(t, err)
	assert.Equal(t, got.ID, got2.ID, "same user resolved from different platforms")
}

func TestResolver_UnknownUser(t *testing.T) {
	users := newMockUserStore() // empty store
	r := identity.NewResolver(users, &mockPairingStore{})

	_, err := r.Resolve(context.Background(), "telegram", "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestResolver_ResolvePlatformUser_MultiplePlatforms(t *testing.T) {
	user := &store.User{
		ID:   "user-multi",
		Name: "Bob",
		Role: "admin",
		Identities: []store.UserIdentity{
			{UserID: "user-multi", Platform: "telegram", PlatformUserID: "tg-bob", DisplayName: "Bob TG"},
			{UserID: "user-multi", Platform: "whatsapp", PlatformUserID: "wa-bob", DisplayName: "Bob WA"},
			{UserID: "user-multi", Platform: "discord", PlatformUserID: "dc-bob", DisplayName: "Bob DC"},
			{UserID: "user-multi", Platform: "slack", PlatformUserID: "sl-bob", DisplayName: "Bob Slack"},
		},
	}

	users := newMockUserStore(user)
	r := identity.NewResolver(users, &mockPairingStore{})
	ctx := context.Background()

	platforms := []struct {
		channelType    string
		platformUserID string
	}{
		{"telegram", "tg-bob"},
		{"whatsapp", "wa-bob"},
		{"discord", "dc-bob"},
		{"slack", "sl-bob"},
	}

	for _, p := range platforms {
		t.Run(p.channelType, func(t *testing.T) {
			got, err := r.Resolve(ctx, p.channelType, p.platformUserID)
			require.NoError(t, err)
			assert.Equal(t, "user-multi", got.ID)
			assert.Equal(t, "Bob", got.Name)
		})
	}
}

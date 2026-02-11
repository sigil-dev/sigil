// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
)

// Compile-time interface satisfaction checks.
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

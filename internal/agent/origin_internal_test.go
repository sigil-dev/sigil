// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
)

// TestOriginFromRole verifies the fallback mapping from MessageRole to provider.Origin
// for legacy messages that have an empty Origin field.
func TestOriginFromRole(t *testing.T) {
	tests := []struct {
		name string
		role store.MessageRole
		want provider.Origin
	}{
		{"user role maps to OriginUser", store.MessageRoleUser, provider.OriginUser},
		{"tool role maps to OriginTool", store.MessageRoleTool, provider.OriginTool},
		{"assistant role maps to OriginSystem", store.MessageRoleAssistant, provider.OriginSystem},
		{"system role maps to OriginSystem", store.MessageRoleSystem, provider.OriginSystem},
		{"unknown role maps to OriginSystem", store.MessageRole("unknown"), provider.OriginSystem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := originFromRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}

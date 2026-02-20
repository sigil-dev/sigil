// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/sigil-dev/sigil/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestOriginFromRole verifies the fallback mapping from MessageRole to types.Origin
// for legacy messages that have an empty Origin field.
func TestOriginFromRole(t *testing.T) {
	tests := []struct {
		name string
		role store.MessageRole
		want types.Origin
	}{
		{"user role maps to OriginUserInput", store.MessageRoleUser, types.OriginUserInput},
		{"tool role maps to OriginToolOutput", store.MessageRoleTool, types.OriginToolOutput},
		{"assistant role maps to OriginSystem", store.MessageRoleAssistant, types.OriginSystem},
		{"system role maps to OriginSystem", store.MessageRoleSystem, types.OriginSystem},
		{"unknown role maps to OriginSystem", store.MessageRole("unknown"), types.OriginSystem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := originFromRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}

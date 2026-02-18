// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOriginConstants_Valid(t *testing.T) {
	tests := []struct {
		name   string
		origin Origin
	}{
		{"OriginUserInput", OriginUserInput},
		{"OriginSystem", OriginSystem},
		{"OriginToolOutput", OriginToolOutput},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.origin.Valid(), "origin constant %q must pass Valid()", tt.origin)
		})
	}
}

func TestOrigin_Valid_RejectsUnknown(t *testing.T) {
	unknown := Origin("unknown")
	assert.False(t, unknown.Valid())
}

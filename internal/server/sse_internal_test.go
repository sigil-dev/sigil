// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType SSEEventType
		want      bool
	}{
		{
			name:      "valid plain event type",
			eventType: "text_delta",
			want:      true,
		},
		{
			name:      "valid event type with dots",
			eventType: "tool.call.result",
			want:      true,
		},
		{
			name:      "newline rejected",
			eventType: "text_delta\ninjected: data",
			want:      false,
		},
		{
			name:      "carriage return rejected",
			eventType: "text_delta\rinjected: data",
			want:      false,
		},
		{
			name:      "crlf rejected",
			eventType: "text_delta\r\ninjected: data",
			want:      false,
		},
		{
			name:      "empty string is valid",
			eventType: "",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateEventType(tt.eventType)
			assert.Equal(t, tt.want, got)
		})
	}
}

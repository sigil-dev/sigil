// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
)

func TestLifecycleState_Transitions(t *testing.T) {
	tests := []struct {
		name    string
		from    plugin.PluginState
		to      plugin.PluginState
		allowed bool
	}{
		{"discovered to validating", plugin.StateDiscovered, plugin.StateValidating, true},
		{"validating to loading", plugin.StateValidating, plugin.StateLoading, true},
		{"loading to running", plugin.StateLoading, plugin.StateRunning, true},
		{"running to draining", plugin.StateRunning, plugin.StateDraining, true},
		{"draining to stopping", plugin.StateDraining, plugin.StateStopping, true},
		{"stopping to stopped", plugin.StateStopping, plugin.StateStopped, true},
		{"validating to error", plugin.StateValidating, plugin.StateError, true},
		{"loading to error", plugin.StateLoading, plugin.StateError, true},
		{"running to error", plugin.StateRunning, plugin.StateError, true},
		// Invalid transitions
		{"discovered to running", plugin.StateDiscovered, plugin.StateRunning, false},
		{"stopped to running", plugin.StateStopped, plugin.StateRunning, false},
		{"running to discovered", plugin.StateRunning, plugin.StateDiscovered, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, plugin.ValidTransition(tt.from, tt.to))
		})
	}
}

func TestPluginInstance_StateTransition(t *testing.T) {
	inst := plugin.NewInstance("telegram", plugin.StateDiscovered)

	assert.Equal(t, plugin.StateDiscovered, inst.State())

	err := inst.TransitionTo(plugin.StateValidating)
	assert.NoError(t, err)
	assert.Equal(t, plugin.StateValidating, inst.State())

	err = inst.TransitionTo(plugin.StateRunning) // invalid: skip loading
	assert.Error(t, err)
	assert.Equal(t, plugin.StateValidating, inst.State()) // state unchanged
}

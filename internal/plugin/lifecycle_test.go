// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"draining to error", plugin.StateDraining, plugin.StateError, true},
		{"stopping to error", plugin.StateStopping, plugin.StateError, true},
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

func TestNewInstanceFromConfig(t *testing.T) {
	cfg := plugin.InstanceConfig{
		Name:         "anthropic",
		Type:         "provider",
		Version:      "1.2.3",
		Tier:         "process",
		Capabilities: []string{"llm.chat", "llm.complete"},
		InitialState: plugin.StateDiscovered,
	}
	inst := plugin.NewInstanceFromConfig(cfg)

	assert.Equal(t, "anthropic", inst.Name())
	assert.Equal(t, "provider", inst.Type())
	assert.Equal(t, "1.2.3", inst.Version())
	assert.Equal(t, "process", inst.Tier())
	assert.Equal(t, []string{"llm.chat", "llm.complete"}, inst.Capabilities())
	assert.Equal(t, plugin.StateDiscovered, inst.State())
}

func TestNewInstanceFromConfig_EmptyCapabilities(t *testing.T) {
	cfg := plugin.InstanceConfig{
		Name:         "simple-tool",
		Type:         "tool",
		Version:      "0.1.0",
		Tier:         "wasm",
		Capabilities: nil,
		InitialState: plugin.StateDiscovered,
	}
	inst := plugin.NewInstanceFromConfig(cfg)

	assert.Equal(t, "simple-tool", inst.Name())
	assert.Equal(t, "tool", inst.Type())
	assert.Equal(t, "0.1.0", inst.Version())
	assert.Equal(t, "wasm", inst.Tier())
	assert.Empty(t, inst.Capabilities())
}

func TestNewInstance_BackwardCompatibility(t *testing.T) {
	// NewInstance should still work, with empty type/version/tier/capabilities.
	inst := plugin.NewInstance("legacy", plugin.StateRunning)

	assert.Equal(t, "legacy", inst.Name())
	assert.Equal(t, plugin.StateRunning, inst.State())
	assert.Equal(t, "", inst.Type())
	assert.Equal(t, "", inst.Version())
	assert.Equal(t, "", inst.Tier())
	assert.Empty(t, inst.Capabilities())
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

func TestPluginInstance_DrainingToError(t *testing.T) {
	inst := plugin.NewInstance("test", plugin.StateDiscovered)
	require.NoError(t, inst.TransitionTo(plugin.StateValidating))
	require.NoError(t, inst.TransitionTo(plugin.StateLoading))
	require.NoError(t, inst.TransitionTo(plugin.StateRunning))
	require.NoError(t, inst.TransitionTo(plugin.StateDraining))

	err := inst.TransitionTo(plugin.StateError)
	assert.NoError(t, err)
	assert.Equal(t, plugin.StateError, inst.State())
}

func TestPluginInstance_StoppingToError(t *testing.T) {
	inst := plugin.NewInstance("test", plugin.StateDiscovered)
	require.NoError(t, inst.TransitionTo(plugin.StateValidating))
	require.NoError(t, inst.TransitionTo(plugin.StateLoading))
	require.NoError(t, inst.TransitionTo(plugin.StateRunning))
	require.NoError(t, inst.TransitionTo(plugin.StateDraining))
	require.NoError(t, inst.TransitionTo(plugin.StateStopping))

	err := inst.TransitionTo(plugin.StateError)
	assert.NoError(t, err)
	assert.Equal(t, plugin.StateError, inst.State())
}

func TestPluginInstance_ConcurrentTransitions(t *testing.T) {
	// Exercises mutex under contention: N goroutines competing to transition.
	const goroutines = 50
	inst := plugin.NewInstance("concurrent", plugin.StateDiscovered)
	require.NoError(t, inst.TransitionTo(plugin.StateValidating))
	require.NoError(t, inst.TransitionTo(plugin.StateLoading))
	require.NoError(t, inst.TransitionTo(plugin.StateRunning))

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	// All goroutines race to transition running → draining.
	// Only one should succeed; the rest get errors (already transitioned).
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := inst.TransitionTo(plugin.StateDraining)
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, successCount, "exactly one goroutine should win the transition")
	assert.Equal(t, plugin.StateDraining, inst.State())
}

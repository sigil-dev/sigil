// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"sync"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// PluginState represents the lifecycle state of a plugin instance.
type PluginState int

const (
	StateDiscovered PluginState = iota
	StateValidating
	StateLoading
	StateRunning
	StateDraining
	StateStopping
	StateStopped
	// StateError is a terminal state by design. When a plugin enters error state,
	// the plugin infrastructure creates a new Instance rather than attempting recovery.
	// This ensures clean error handling and prevents stale plugin state.
	StateError
)

// String returns the human-readable representation of a plugin state.
// Hand-written stringer is used instead of go:generate stringer to avoid build
// complexity for a small, fixed state set and to ensure custom formatting control.
func (s PluginState) String() string {
	switch s {
	case StateDiscovered:
		return "discovered"
	case StateValidating:
		return "validating"
	case StateLoading:
		return "loading"
	case StateRunning:
		return "running"
	case StateDraining:
		return "draining"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// validTransitions defines allowed state transitions as an adjacency list.
var validTransitions = map[PluginState]map[PluginState]bool{
	StateDiscovered: {
		StateValidating: true,
	},
	StateValidating: {
		StateLoading: true,
		StateError:   true,
	},
	StateLoading: {
		StateRunning: true,
		StateError:   true,
	},
	StateRunning: {
		StateDraining: true,
		StateError:    true,
	},
	StateDraining: {
		StateStopping: true,
		StateError:    true,
	},
	StateStopping: {
		StateStopped: true,
		StateError:   true,
	},
	StateStopped: {},
	StateError:   {},
}

// ValidTransition returns true if transitioning from one state to another is allowed.
// Looking up an unknown from state returns nil from the outer map; checking membership
// in a nil map returns false, so out-of-range states safely return false without panic.
func ValidTransition(from, to PluginState) bool {
	allowed, exists := validTransitions[from][to]
	return exists && allowed
}

// Instance represents a plugin instance with lifecycle state management.
type Instance struct {
	mu           sync.RWMutex
	name         string
	pluginType   string
	version      string
	tier         string
	capabilities []string
	state        PluginState
}

// InstanceConfig holds parameters for creating a fully-described plugin instance.
type InstanceConfig struct {
	Name         string
	Type         string
	Version      string
	Tier         string
	Capabilities []string
	InitialState PluginState
}

// NewInstance creates a new plugin instance with the given name and initial state.
// Retained for backward compatibility; use NewInstanceFromConfig for full metadata.
func NewInstance(name string, state PluginState) *Instance {
	return &Instance{
		name:  name,
		state: state,
	}
}

// NewInstanceFromConfig creates a new plugin instance from a full configuration.
func NewInstanceFromConfig(cfg InstanceConfig) *Instance {
	return &Instance{
		name:         cfg.Name,
		pluginType:   cfg.Type,
		version:      cfg.Version,
		tier:         cfg.Tier,
		capabilities: cfg.Capabilities,
		state:        cfg.InitialState,
	}
}

// Name returns the plugin instance name.
func (i *Instance) Name() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.name
}

// Type returns the plugin type (provider, channel, tool, skill).
func (i *Instance) Type() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.pluginType
}

// Version returns the plugin version.
func (i *Instance) Version() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.version
}

// Tier returns the execution tier (wasm, process, container).
func (i *Instance) Tier() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.tier
}

// Capabilities returns the granted capability patterns.
func (i *Instance) Capabilities() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.capabilities
}

// State returns the current plugin state.
func (i *Instance) State() PluginState {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}

// TransitionTo attempts to transition to a new state. Returns an error if the
// transition is not valid.
func (i *Instance) TransitionTo(newState PluginState) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if !ValidTransition(i.state, newState) {
		return sigilerr.Errorf(sigilerr.CodePluginLifecycleTransitionInvalid,
			"invalid state transition: %s -> %s", i.state, newState)
	}

	i.state = newState
	return nil
}

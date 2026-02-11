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
	StateError
)

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
	},
	StateStopping: {
		StateStopped: true,
	},
	StateStopped: {},
	StateError:   {},
}

// ValidTransition returns true if transitioning from one state to another is allowed.
func ValidTransition(from, to PluginState) bool {
	allowed, exists := validTransitions[from][to]
	return exists && allowed
}

// Instance represents a plugin instance with lifecycle state management.
type Instance struct {
	mu    sync.RWMutex
	name  string
	state PluginState
}

// NewInstance creates a new plugin instance with the given name and initial state.
func NewInstance(name string, state PluginState) *Instance {
	return &Instance{
		name:  name,
		state: state,
	}
}

// Name returns the plugin instance name.
func (i *Instance) Name() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.name
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

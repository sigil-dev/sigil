// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package wasm

import (
	"context"
	"strings"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Host wraps a Wazero runtime with optional execution timeout.
type Host struct {
	runtime     wazero.Runtime
	execTimeout time.Duration
}

// Option configures a Host.
type Option func(*Host)

// WithExecTimeout sets the maximum execution duration for module function calls.
// A zero or negative value means no timeout.
func WithExecTimeout(d time.Duration) Option {
	return func(h *Host) {
		h.execTimeout = d
	}
}

// NewHost creates a Wazero runtime with the given options applied.
// The runtime is configured with WithCloseOnContextDone(true) so that
// context cancellation interrupts in-flight Wasm execution.
func NewHost(opts ...Option) (*Host, error) {
	h := &Host{}
	for _, o := range opts {
		o(h)
	}

	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	h.runtime = wazero.NewRuntimeWithConfig(context.Background(), cfg)

	return h, nil
}

// ExecTimeout returns the configured execution timeout (zero if unset).
func (h *Host) ExecTimeout() time.Duration {
	return h.execTimeout
}

// LoadModule compiles and instantiates a Wasm module.
// Rejects empty or whitespace-only names.
func (h *Host) LoadModule(ctx context.Context, name string, wasmBytes []byte) (*Module, error) {
	if strings.TrimSpace(name) == "" {
		return nil, sigilerr.Errorf(sigilerr.CodePluginRuntimeStartFailure,
			"module name must not be empty")
	}

	compiled, err := h.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"compiling wasm module %s", name)
	}

	instance, err := h.runtime.InstantiateModule(ctx, compiled,
		wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"instantiating wasm module %s", name)
	}

	return &Module{
		name:        name,
		compiled:    compiled,
		instance:    instance,
		execTimeout: h.execTimeout,
	}, nil
}

// Close shuts down the runtime and releases resources.
func (h *Host) Close() error {
	return h.runtime.Close(context.Background())
}

// Module represents a compiled and instantiated Wasm module.
type Module struct {
	name        string
	compiled    wazero.CompiledModule
	instance    api.Module
	execTimeout time.Duration
}

// Name returns the module's registered name.
func (m *Module) Name() string {
	return m.name
}

// Close releases the module instance.
func (m *Module) Close(ctx context.Context) error {
	return m.instance.Close(ctx)
}

// CallWithTimeout invokes an exported function, wrapping the context
// with the host's execTimeout if configured.
func (m *Module) CallWithTimeout(ctx context.Context, fnName string, params ...uint64) ([]uint64, error) {
	if m.execTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.execTimeout)
		defer cancel()
	}

	fn := m.instance.ExportedFunction(fnName)
	if fn == nil {
		return nil, sigilerr.Errorf(sigilerr.CodePluginRuntimeCallFailure,
			"function %q not exported by module %s", fnName, m.name)
	}

	results, err := fn.Call(ctx, params...)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure,
			"calling function %q in module %s", fnName, m.name)
	}

	return results, nil
}

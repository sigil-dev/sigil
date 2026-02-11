// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package wasm

import (
	"context"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type Host struct {
	runtime wazero.Runtime
}

type Option func(*Host)

func NewHost(_ ...Option) (*Host, error) {
	ctx := context.Background()
	return &Host{
		runtime: wazero.NewRuntime(ctx),
	}, nil
}

func (h *Host) LoadModule(ctx context.Context, name string, wasmBytes []byte) (*Module, error) {
	compiled, err := h.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"compiling wasm module %s", name)
	}

	instance, err := h.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"instantiating wasm module %s", name)
	}

	return &Module{
		name:     name,
		compiled: compiled,
		instance: instance,
	}, nil
}

func (h *Host) Close() error {
	return h.runtime.Close(context.Background())
}

type Module struct {
	name     string
	compiled wazero.CompiledModule
	instance api.Module
}

func (m *Module) Name() string {
	return m.name
}

func (m *Module) Close(ctx context.Context) error {
	return m.instance.Close(ctx)
}

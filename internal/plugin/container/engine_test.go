// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container

import (
	"context"
	"errors"
	"testing"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOCIEngineCreateRestrictedNetworkBuildsIsolationFlags(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{"ctr-123"},
	}
	engine := newOCIEngineWithRunner("docker", runner)

	id, err := engine.Create(context.Background(), CreateContainerRequest{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
	})
	require.NoError(t, err)
	assert.Equal(t, "ctr-123", id)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, "docker", runner.calls[0].name)
	assert.Contains(t, runner.calls[0].args, "--read-only")
	assert.Contains(t, runner.calls[0].args, "--cap-drop")
	assert.Contains(t, runner.calls[0].args, "ALL")
	assert.Contains(t, runner.calls[0].args, "--memory")
	assert.Contains(t, runner.calls[0].args, "268435456")
	assert.Contains(t, runner.calls[0].args, "--publish")
	assert.Contains(t, runner.calls[0].args, "127.0.0.1:50051:50051/tcp")
	assert.Contains(t, runner.calls[0].args, "ghcr.io/org/python-tool:latest")
}

func TestOCIEngineCreateHostNetworkSkipsPortPublish(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{"ctr-123"},
	}
	engine := newOCIEngineWithRunner("docker", runner)

	_, err := engine.Create(context.Background(), CreateContainerRequest{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkHost,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
	})
	require.NoError(t, err)
	require.Len(t, runner.calls, 1)
	assert.Contains(t, runner.calls[0].args, "host")
	assert.NotContains(t, runner.calls[0].args, "--publish")
}

func TestOCIEngineCreateValidatesRequest(t *testing.T) {
	runner := &fakeRunner{}
	engine := newOCIEngineWithRunner("docker", runner)

	_, err := engine.Create(context.Background(), CreateContainerRequest{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 0,
		GRPCPort:         50051,
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	assert.Empty(t, runner.calls)
}

func TestOCIEngineLifecycleCommands(t *testing.T) {
	runner := &fakeRunner{}
	engine := newOCIEngineWithRunner("docker", runner)

	require.NoError(t, engine.Start(context.Background(), "ctr-1"))
	require.NoError(t, engine.Stop(context.Background(), "ctr-1", 5*time.Second))
	require.NoError(t, engine.Remove(context.Background(), "ctr-1"))

	require.Len(t, runner.calls, 3)
	assert.Equal(t, commandCall{name: "docker", args: []string{"start", "ctr-1"}}, runner.calls[0])
	assert.Equal(t, commandCall{name: "docker", args: []string{"stop", "--time", "5", "ctr-1"}}, runner.calls[1])
	assert.Equal(t, commandCall{name: "docker", args: []string{"rm", "--force", "ctr-1"}}, runner.calls[2])
}

func TestOCIEngineLifecycleCommandErrors(t *testing.T) {
	runner := &fakeRunner{
		errors: []error{
			errors.New("start failed"),
			errors.New("stop failed"),
			errors.New("remove failed"),
		},
	}
	engine := newOCIEngineWithRunner("docker", runner)

	assert.Error(t, engine.Start(context.Background(), "ctr-1"))
	assert.Error(t, engine.Stop(context.Background(), "ctr-1", 5*time.Second))
	assert.Error(t, engine.Remove(context.Background(), "ctr-1"))
}

func TestRuntimeLifecycleWithOCIEngineSuccess(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{
			"ctr-123", // create
			"",        // start
			"",        // stop
			"",        // remove
		},
	}
	runtime := NewRuntime(newOCIEngineWithRunner("docker", runner))

	inst, err := runtime.Start(context.Background(), ContainerConfig{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, "ctr-123", inst.ID)
	assert.Equal(t, "127.0.0.1:50051", inst.Endpoint)

	require.NoError(t, runtime.Stop(context.Background(), inst.ID))
	require.Len(t, runner.calls, 4)
	assert.Equal(t, commandCall{name: "docker", args: []string{"stop", "--time", "5", "ctr-123"}}, runner.calls[2])
	assert.Equal(t, commandCall{name: "docker", args: []string{"rm", "--force", "ctr-123"}}, runner.calls[3])
}

func TestRuntimeLifecycleWithOCIEngineStartFailure(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{
			"ctr-123", // create
			"",        // start
			"",        // remove cleanup after start failure
		},
		errors: []error{
			nil,
			errors.New("start failed"),
			nil,
		},
	}
	runtime := NewRuntime(newOCIEngineWithRunner("docker", runner))

	_, err := runtime.Start(context.Background(), ContainerConfig{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeStartFailure))
	require.Len(t, runner.calls, 3)
	assert.Equal(t, commandCall{name: "docker", args: []string{"rm", "--force", "ctr-123"}}, runner.calls[2])
}

type commandCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls   []commandCall
	outputs []string
	errors  []error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, commandCall{name: name, args: args})
	idx := len(f.calls) - 1

	var out string
	if idx < len(f.outputs) {
		out = f.outputs[idx]
	}
	if idx < len(f.errors) && f.errors[idx] != nil {
		return out, f.errors[idx]
	}
	return out, nil
}

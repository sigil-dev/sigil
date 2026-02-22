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
	assert.Contains(t, runner.calls[0].args, "--network")
	assert.Contains(t, runner.calls[0].args, "bridge")
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

func TestOCIEngineCreateDoesNotPassDetachFlag(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{"ctr-123"},
	}
	engine := newOCIEngineWithRunner("docker", runner)

	_, err := engine.Create(context.Background(), CreateContainerRequest{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
	})
	require.NoError(t, err)
	require.Len(t, runner.calls, 1)
	assert.NotContains(t, runner.calls[0].args, "--detach")
}

func TestOCIEngineCreateRejectsInvalidPluginName(t *testing.T) {
	tests := []struct {
		name       string
		pluginName string
	}{
		{"blank name", ""},
		{"whitespace only", "   "},
		{"all special chars", "!!!"},
		{"only hyphens after sanitization", "@@@"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := newOCIEngineWithRunner("docker", runner)

			_, err := engine.Create(context.Background(), CreateContainerRequest{
				PluginName:       tt.pluginName,
				Image:            "ghcr.io/org/test:latest",
				NetworkMode:      NetworkRestricted,
				MemoryLimitBytes: 256 * 1024 * 1024,
				GRPCPort:         50051,
			})
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
			assert.Empty(t, runner.calls, "runner must not be invoked for invalid plugin names")
		})
	}
}

func TestOCIEngineCreateReturnsErrorOnEmptyContainerID(t *testing.T) {
	runner := &fakeRunner{
		outputs: []string{""},
	}
	engine := newOCIEngineWithRunner("docker", runner)

	_, err := engine.Create(context.Background(), CreateContainerRequest{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
	})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeStartFailure))
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

func TestNewOCIEngineWithRunnerDefaultsToDocker(t *testing.T) {
	tests := []struct {
		name          string
		runtimeBinary string
		wantBinary    string
	}{
		{"empty string", "", "docker"},
		{"whitespace only", "   ", "docker"},
		{"tab and spaces", " \t ", "docker"},
		{"explicit podman", "podman", "podman"},
		{"padded binary", " nerdctl ", "nerdctl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{outputs: []string{"ctr-1"}}
			engine := newOCIEngineWithRunner(tt.runtimeBinary, runner)

			_, err := engine.Create(context.Background(), CreateContainerRequest{
				PluginName:       "test-plugin",
				Image:            "ghcr.io/org/test:latest",
				NetworkMode:      NetworkRestricted,
				MemoryLimitBytes: 256 * 1024 * 1024,
				GRPCPort:         50051,
			})
			require.NoError(t, err)
			require.Len(t, runner.calls, 1)
			assert.Equal(t, tt.wantBinary, runner.calls[0].name)
		})
	}
}

func TestContainerNameSanitizesSpecialCharacters(t *testing.T) {
	tests := []struct {
		name       string
		pluginName string
		want       string
	}{
		{"simple name", "python-tool", "sigil-python-tool"},
		{"underscores preserved", "my_plugin", "sigil-my_plugin"},
		{"spaces replaced", "my plugin", "sigil-my-plugin"},
		{"dots preserved", "my.plugin", "sigil-my.plugin"},
		{"slashes replaced", "org/tool", "sigil-org-tool"},
		{"mixed special chars", "org/my_plugin.v2 beta", "sigil-org-my_plugin.v2-beta"},
		{"uppercase lowered", "MyPlugin", "sigil-myplugin"},
		{"leading/trailing spaces trimmed", "  spaced  ", "sigil-spaced"},
		{"at sign replaced", "user@host", "sigil-user-host"},
		{"colons replaced", "image:latest", "sigil-image-latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containerName(tt.pluginName)
			assert.Equal(t, tt.want, got)
		})
	}
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

func TestNetworkArg(t *testing.T) {
	tests := []struct {
		name    string
		mode    NetworkMode
		want    string
		wantErr bool
	}{
		{"NetworkNone returns none", NetworkNone, "none", false},
		{"NetworkHost returns host", NetworkHost, "host", false},
		{"NetworkRestricted returns bridge", NetworkRestricted, "bridge", false},
		{"unknown mode returns error", NetworkMode("unknown"), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := networkArg(tt.mode)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/plugin/container"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerConfigFromManifest(t *testing.T) {
	manifest := &plugin.Manifest{
		Name: "python-tool",
		Execution: plugin.ExecutionConfig{
			Tier:        plugin.TierContainer,
			Image:       "ghcr.io/org/python-tool:latest",
			Network:     "restricted",
			MemoryLimit: "256Mi",
		},
	}

	cfg, err := container.ConfigFromManifest(manifest)
	require.NoError(t, err)
	assert.Equal(t, "python-tool", cfg.PluginName)
	assert.Equal(t, "ghcr.io/org/python-tool:latest", cfg.Image)
	assert.Equal(t, container.NetworkRestricted, cfg.NetworkMode)
	assert.Equal(t, int64(256*1024*1024), cfg.MemoryLimitBytes)
	assert.Equal(t, container.DefaultGRPCPort, cfg.GRPCPort)
	assert.Equal(t, container.DefaultStopTimeout, cfg.StopTimeout)
}

func TestContainerConfigFromManifestValidation(t *testing.T) {
	t.Run("requires container tier", func(t *testing.T) {
		manifest := &plugin.Manifest{
			Name: "bad",
			Execution: plugin.ExecutionConfig{
				Tier:        plugin.TierProcess,
				Image:       "ghcr.io/org/tool:latest",
				Network:     "restricted",
				MemoryLimit: "256Mi",
			},
		}

		_, err := container.ConfigFromManifest(manifest)
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	})

	t.Run("requires image", func(t *testing.T) {
		manifest := &plugin.Manifest{
			Name: "bad",
			Execution: plugin.ExecutionConfig{
				Tier:        plugin.TierContainer,
				Network:     "restricted",
				MemoryLimit: "256Mi",
			},
		}

		_, err := container.ConfigFromManifest(manifest)
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	})

	t.Run("requires memory limit", func(t *testing.T) {
		manifest := &plugin.Manifest{
			Name: "bad",
			Execution: plugin.ExecutionConfig{
				Tier:    plugin.TierContainer,
				Image:   "ghcr.io/org/tool:latest",
				Network: "restricted",
			},
		}

		_, err := container.ConfigFromManifest(manifest)
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	})
}

func TestParseMemoryLimit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{name: "ki", input: "512Ki", want: 512 * 1024},
		{name: "mi", input: "256Mi", want: 256 * 1024 * 1024},
		{name: "gi", input: "1Gi", want: 1024 * 1024 * 1024},
		{name: "bytes", input: "4096", want: 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := container.ParseMemoryLimit(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMemoryLimitInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "invalid suffix", input: "256MB"},
		{name: "negative", input: "-1Mi"},
		{name: "zero", input: "0"},
		{name: "non numeric", input: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := container.ParseMemoryLimit(tt.input)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue))
		})
	}
}

func TestValidateImage(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		wantErr bool
	}{
		{name: "ghcr", image: "ghcr.io/org/tool:latest"},
		{name: "dockerhub", image: "docker.io/library/python:3.12"},
		{name: "empty", image: "", wantErr: true},
		{name: "relative path", image: "../relative/path", wantErr: true},
		{name: "whitespace", image: "ghcr.io/org/tool latest", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := container.ValidateImage(tt.image)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNetworkModeValues(t *testing.T) {
	assert.Equal(t, container.NetworkMode("none"), container.NetworkNone)
	assert.Equal(t, container.NetworkMode("restricted"), container.NetworkRestricted)
	assert.Equal(t, container.NetworkMode("host"), container.NetworkHost)
}

func TestRuntimeLifecycleStartStopSuccess(t *testing.T) {
	engine := &fakeEngine{createID: "ctr-1"}
	runtime := container.NewRuntime(engine)
	cfg := container.ContainerConfig{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      container.NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	}

	inst, err := runtime.Start(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "ctr-1", inst.ID)
	assert.Equal(t, "127.0.0.1:50051", inst.Endpoint)
	assert.Equal(t, []string{"create", "start"}, engine.calls)

	err = runtime.Stop(context.Background(), inst.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"create", "start", "stop", "remove"}, engine.calls)
}

func TestRuntimeLifecycleStartFailureCleansUp(t *testing.T) {
	engine := &fakeEngine{
		createID:  "ctr-2",
		startErr:  errors.New("boom"),
		removeErr: errors.New("remove must not mask start error"),
	}
	runtime := container.NewRuntime(engine)
	cfg := container.ContainerConfig{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      container.NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	}

	_, err := runtime.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeStartFailure))
	assert.Equal(t, []string{"create", "start", "remove"}, engine.calls)
}

func TestRuntimeLifecycleStopFailure(t *testing.T) {
	engine := &fakeEngine{stopErr: errors.New("stop failed")}
	runtime := container.NewRuntime(engine)

	err := runtime.Stop(context.Background(), "ctr-stop")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeCallFailure))
	assert.Equal(t, []string{"stop"}, engine.calls)
}

func TestRuntimeLifecycleStartRejectsInvalidConfig(t *testing.T) {
	engine := &fakeEngine{}
	runtime := container.NewRuntime(engine)

	_, err := runtime.Start(context.Background(), container.ContainerConfig{})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	assert.Empty(t, engine.calls)
}

type fakeEngine struct {
	calls     []string
	createID  string
	createReq container.CreateContainerRequest
	createErr error
	startErr  error
	stopErr   error
	removeErr error
}

func (f *fakeEngine) Create(_ context.Context, req container.CreateContainerRequest) (string, error) {
	f.calls = append(f.calls, "create")
	f.createReq = req
	if f.createErr != nil {
		return "", f.createErr
	}
	if f.createID == "" {
		f.createID = "ctr-generated"
	}
	return f.createID, nil
}

func (f *fakeEngine) Start(_ context.Context, _ string) error {
	f.calls = append(f.calls, "start")
	return f.startErr
}

func (f *fakeEngine) Stop(_ context.Context, _ string, _ time.Duration) error {
	f.calls = append(f.calls, "stop")
	return f.stopErr
}

func (f *fakeEngine) Remove(_ context.Context, _ string) error {
	f.calls = append(f.calls, "remove")
	return f.removeErr
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/plugin/container"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerConfigFromManifest(t *testing.T) {
	tests := []struct {
		name            string
		manifest        *plugin.Manifest
		wantNetworkMode container.NetworkMode
	}{
		{
			name: "explicit restricted network",
			manifest: &plugin.Manifest{
				Name: "python-tool",
				Execution: plugin.ExecutionConfig{
					Tier:        plugin.TierContainer,
					Image:       "ghcr.io/org/python-tool:latest",
					Network:     "restricted",
					MemoryLimit: "256Mi",
				},
			},
			wantNetworkMode: container.NetworkRestricted,
		},
		{
			name: "empty network defaults to restricted",
			manifest: &plugin.Manifest{
				Name: "python-tool",
				Execution: plugin.ExecutionConfig{
					Tier:        plugin.TierContainer,
					Image:       "ghcr.io/org/python-tool:latest",
					Network:     "",
					MemoryLimit: "256Mi",
				},
			},
			wantNetworkMode: container.NetworkRestricted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := container.ConfigFromManifest(tt.manifest)
			require.NoError(t, err)
			assert.Equal(t, "python-tool", cfg.PluginName)
			assert.Equal(t, "ghcr.io/org/python-tool:latest", cfg.Image)
			assert.Equal(t, tt.wantNetworkMode, cfg.NetworkMode)
			assert.Equal(t, int64(256*1024*1024), cfg.MemoryLimitBytes)
			assert.Equal(t, container.DefaultGRPCPort, cfg.GRPCPort)
			assert.Equal(t, container.DefaultStopTimeout, cfg.StopTimeout)
		})
	}
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

	t.Run("invalid network mode", func(t *testing.T) {
		manifest := &plugin.Manifest{
			Name: "bad",
			Execution: plugin.ExecutionConfig{
				Tier:        plugin.TierContainer,
				Image:       "ghcr.io/org/tool:latest",
				Network:     "macvlan",
				MemoryLimit: "256Mi",
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
			got, err := plugin.ParseMemoryLimit(tt.input)
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
		{name: "overflow gi", input: "9999999999999Gi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := plugin.ParseMemoryLimit(tt.input)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue))
		})
	}
}

func TestRuntimeLifecycleStopWithUnknownIDUsesDefaultTimeout(t *testing.T) {
	engine := &fakeEngine{createID: "ctr-known"}
	runtime := container.NewRuntime(engine)

	// Stop an ID that was never registered via Start — runtime falls back to DefaultStopTimeout.
	err := runtime.Stop(context.Background(), "unknown-ctr")
	require.NoError(t, err)
	assert.Equal(t, []string{"stop", "remove"}, engine.calls)
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
		{name: "absolute path", image: "/etc/passwd", wantErr: true},
		{name: "path traversal mid-ref", image: "registry.io/org/../evil:latest", wantErr: true},
		{name: "digest pinned", image: "ghcr.io/org/tool@sha256:abc123def456"},
		{name: "tag and digest", image: "ghcr.io/org/tool:v1.0@sha256:abc123def456"},
		{name: "bare at sign", image: "ghcr.io/org/tool@something"},
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

func TestRuntimeStopUsesRegisteredStopTimeout(t *testing.T) {
	engine := &fakeEngine{createID: "ctr-timeout"}
	runtime := container.NewRuntime(engine)

	const customTimeout = 30 * time.Second
	cfg := container.ContainerConfig{
		PluginName:       "timeout-tool",
		Image:            "ghcr.io/org/timeout-tool:latest",
		NetworkMode:      container.NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      customTimeout,
	}

	inst, err := runtime.Start(context.Background(), cfg)
	require.NoError(t, err)

	err = runtime.Stop(context.Background(), inst.ID)
	require.NoError(t, err)

	require.Len(t, engine.stopTimeouts, 1, "engine.Stop must be called exactly once")
	assert.Equal(t, customTimeout, engine.stopTimeouts[0],
		"engine.Stop must receive the per-container StopTimeout registered by Start, not DefaultStopTimeout")
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

func TestRuntimeLifecycleStartCreateFailure(t *testing.T) {
	engine := &fakeEngine{createErr: errors.New("create failed")}
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
	// engine.Create was called, but engine.Start must NOT have been called.
	assert.Equal(t, []string{"create"}, engine.calls)
	// No container was registered, so stopTimeouts must be empty.
	assert.Empty(t, runtime.StopTimeouts())
}

func TestRuntimeLifecycleStopFailure(t *testing.T) {
	engine := &fakeEngine{stopErr: errors.New("stop failed")}
	runtime := container.NewRuntime(engine)

	err := runtime.Stop(context.Background(), "ctr-stop")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeCallFailure))
	assert.Equal(t, []string{"stop"}, engine.calls)
}

func TestRuntimeLifecycleRemoveFailureClearsTimeout(t *testing.T) {
	engine := &fakeEngine{createID: "ctr-rm", removeErr: errors.New("rm failed")}
	runtime := container.NewRuntime(engine)

	// Start registers the container's stop timeout in the runtime's internal map.
	cfg := container.ContainerConfig{
		PluginName:       "rm-fail-tool",
		Image:            "ghcr.io/org/rm-fail-tool:latest",
		NetworkMode:      container.NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	}
	inst, err := runtime.Start(context.Background(), cfg)
	require.NoError(t, err)
	assert.Contains(t, runtime.StopTimeouts(), inst.ID, "stop timeout should be registered after Start")

	// Stop succeeds for the engine stop call but Remove fails.
	// The error includes the container ID so the caller can invoke Remove directly.
	err = runtime.Stop(context.Background(), inst.ID)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeCallFailure))
	assert.Contains(t, err.Error(), "removing container")
	assert.Contains(t, err.Error(), inst.ID, "error must include container ID so caller can invoke Remove directly")
	assert.Equal(t, []string{"create", "start", "stop", "remove"}, engine.calls)

	// The stopTimeouts entry is deleted unconditionally before Remove is attempted.
	// A subsequent Stop call would use DefaultStopTimeout; callers must invoke Remove directly.
	assert.NotContains(t, runtime.StopTimeouts(), inst.ID, "stop timeout must be deleted after Stop even when Remove fails")
}

func TestRuntimeLifecycleStartRejectsNetworkNone(t *testing.T) {
	engine := &fakeEngine{createID: "ctr-none"}
	runtime := container.NewRuntime(engine)
	cfg := container.ContainerConfig{
		PluginName:       "isolated-tool",
		Image:            "ghcr.io/org/isolated-tool:latest",
		NetworkMode:      container.NetworkNone,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	}

	_, err := runtime.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeConfigInvalid))
	assert.Contains(t, err.Error(), "NetworkNone is not supported for gRPC plugins")
	assert.Empty(t, engine.calls)
}

func TestRuntimeStopRejectsEmptyContainerID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
		{"tab and spaces", " \t "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &fakeEngine{}
			runtime := container.NewRuntime(engine)

			err := runtime.Stop(context.Background(), tt.id)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginRuntimeCallFailure))
			assert.Contains(t, err.Error(), "container id must not be empty")
			assert.Empty(t, engine.calls)
		})
	}
}

func TestRuntimeLifecycleStartRejectsInvalidConfig(t *testing.T) {
	engine := &fakeEngine{}
	runtime := container.NewRuntime(engine)

	_, err := runtime.Start(context.Background(), container.ContainerConfig{})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
	assert.Empty(t, engine.calls)
}

func TestContainerConfigValidateBoundaries(t *testing.T) {
	// baseline is a fully valid config; each test overrides one field to isolate the boundary.
	baseline := container.ContainerConfig{
		PluginName:       "python-tool",
		Image:            "ghcr.io/org/python-tool:latest",
		NetworkMode:      container.NetworkRestricted,
		MemoryLimitBytes: 256 * 1024 * 1024,
		GRPCPort:         50051,
		StopTimeout:      5 * time.Second,
	}

	tests := []struct {
		name    string
		cfg     container.ContainerConfig
		wantErr bool
	}{
		{
			name:    "port 0 is invalid",
			cfg:     func() container.ContainerConfig { c := baseline; c.GRPCPort = 0; return c }(),
			wantErr: true,
		},
		{
			name:    "port 65535 is valid (max port)",
			cfg:     func() container.ContainerConfig { c := baseline; c.GRPCPort = 65535; return c }(),
			wantErr: false,
		},
		{
			name:    "port 65536 is out of range",
			cfg:     func() container.ContainerConfig { c := baseline; c.GRPCPort = 65536; return c }(),
			wantErr: true,
		},
		{
			name:    "zero StopTimeout is invalid",
			cfg:     func() container.ContainerConfig { c := baseline; c.StopTimeout = 0; return c }(),
			wantErr: true,
		},
		{
			name:    "negative StopTimeout is invalid",
			cfg:     func() container.ContainerConfig { c := baseline; c.StopTimeout = -1 * time.Second; return c }(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodePluginManifestValidateInvalid))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRuntimeNilEngineGuard(t *testing.T) {
	tests := []struct {
		name     string
		call     func(r *container.Runtime) error
		wantCode sigilerr.Code
	}{
		{
			name: "Start returns CodePluginRuntimeStartFailure",
			call: func(r *container.Runtime) error {
				cfg := container.ContainerConfig{
					PluginName:       "test-plugin",
					Image:            "ghcr.io/org/test:latest",
					NetworkMode:      container.NetworkRestricted,
					MemoryLimitBytes: 256 * 1024 * 1024,
					GRPCPort:         50051,
					StopTimeout:      5 * time.Second,
				}
				_, err := r.Start(context.Background(), cfg)
				return err
			},
			wantCode: sigilerr.CodePluginRuntimeStartFailure,
		},
		{
			name: "Stop returns CodePluginRuntimeCallFailure",
			call: func(r *container.Runtime) error {
				return r.Stop(context.Background(), "ctr-1")
			},
			wantCode: sigilerr.CodePluginRuntimeCallFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &container.Runtime{}
			err := tt.call(r)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode))
		})
	}
}

func TestRuntimeConcurrentStartStop(t *testing.T) {
	engine := &safeFakeEngine{}
	runtime := container.NewRuntime(engine)

	const workers = 10
	var wg sync.WaitGroup

	insts := make([]*container.ContainerInstance, workers)
	var mu sync.Mutex
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := container.ContainerConfig{
				PluginName:       fmt.Sprintf("plugin-%d", i),
				Image:            "docker.io/test:latest",
				NetworkMode:      container.NetworkRestricted,
				MemoryLimitBytes: 64 * 1024 * 1024,
				GRPCPort:         50051 + i,
				StopTimeout:      time.Second,
			}
			inst, err := runtime.Start(context.Background(), cfg)
			if err == nil {
				mu.Lock()
				insts[i] = inst
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	for _, inst := range insts {
		if inst == nil {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = runtime.Stop(context.Background(), id)
		}(inst.ID)
	}
	wg.Wait()
}

// safeFakeEngine is a thread-safe Engine implementation for concurrency tests.
type safeFakeEngine struct {
	mu      sync.Mutex
	counter int
}

func (f *safeFakeEngine) Create(_ context.Context, _ container.CreateContainerRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	return fmt.Sprintf("ctr-%d", f.counter), nil
}

func (f *safeFakeEngine) Start(_ context.Context, _ string) error { return nil }

func (f *safeFakeEngine) Stop(_ context.Context, _ string, _ time.Duration) error { return nil }

func (f *safeFakeEngine) Remove(_ context.Context, _ string) error { return nil }

type fakeEngine struct {
	calls        []string
	createID     string
	createReq    container.CreateContainerRequest
	createErr    error
	startErr     error
	stopErr      error
	removeErr    error
	stopTimeouts []time.Duration
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

func (f *fakeEngine) Stop(_ context.Context, _ string, timeout time.Duration) error {
	f.calls = append(f.calls, "stop")
	f.stopTimeouts = append(f.stopTimeouts, timeout)
	return f.stopErr
}

func (f *fakeEngine) Remove(_ context.Context, _ string) error {
	f.calls = append(f.calls, "remove")
	return f.removeErr
}

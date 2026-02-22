// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sigil-dev/sigil/internal/plugin"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const (
	// DefaultGRPCPort is the default in-container plugin gRPC port.
	DefaultGRPCPort = 50051
	// DefaultStopTimeout is used when no explicit stop timeout is configured.
	DefaultStopTimeout = 10 * time.Second
)

// NetworkMode controls container network isolation.
type NetworkMode string

const (
	NetworkNone       NetworkMode = "none"
	NetworkRestricted NetworkMode = "restricted"
	NetworkHost       NetworkMode = "host"
)

var (
	imagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./:_-]*$`)
)

// ContainerConfig captures runtime settings for container-tier plugin execution.
type ContainerConfig struct {
	PluginName       string
	Image            string
	NetworkMode      NetworkMode
	MemoryLimitBytes int64
	GRPCPort         int
	StopTimeout      time.Duration
}

// Validate checks runtime configuration before container lifecycle operations.
func (c ContainerConfig) Validate() error {
	if strings.TrimSpace(c.PluginName) == "" {
		return sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "container config: plugin name must not be empty")
	}
	if err := ValidateImage(c.Image); err != nil {
		return err
	}
	if err := plugin.ValidateContainerNetworkMode(string(c.NetworkMode)); err != nil {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"container config: network mode must be one of [none, restricted, host], got %q", c.NetworkMode)
	}
	if c.MemoryLimitBytes <= 0 {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"container config: memory_limit must be > 0, got %d", c.MemoryLimitBytes)
	}
	if c.GRPCPort <= 0 || c.GRPCPort > 65535 {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"container config: grpc port must be in range 1..65535, got %d", c.GRPCPort)
	}
	if c.StopTimeout <= 0 {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"container config: stop timeout must be > 0, got %s", c.StopTimeout)
	}

	return nil
}

// ConfigFromManifest converts container execution settings from a manifest to runtime config.
func ConfigFromManifest(manifest *plugin.Manifest) (*ContainerConfig, error) {
	if manifest == nil {
		return nil, sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "manifest must not be nil")
	}
	if manifest.Execution.Tier != plugin.TierContainer {
		return nil, sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"container config requires execution tier %q, got %q",
			plugin.TierContainer, manifest.Execution.Tier)
	}

	if strings.TrimSpace(manifest.Execution.MemoryLimit) == "" {
		return nil, sigilerr.New(sigilerr.CodePluginManifestValidateInvalid,
			"container config requires execution.memory_limit")
	}

	memBytes, err := plugin.ParseMemoryLimit(manifest.Execution.MemoryLimit)
	if err != nil {
		return nil, sigilerr.Wrap(err, sigilerr.CodePluginManifestValidateInvalid, "invalid execution.memory_limit")
	}

	mode := NetworkRestricted
	if strings.TrimSpace(manifest.Execution.Network) != "" {
		mode = NetworkMode(strings.TrimSpace(manifest.Execution.Network))
	}

	cfg := &ContainerConfig{
		PluginName:       manifest.Name,
		Image:            manifest.Execution.Image,
		NetworkMode:      mode,
		MemoryLimitBytes: memBytes,
		GRPCPort:         DefaultGRPCPort,
		StopTimeout:      DefaultStopTimeout,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidateImage performs basic validation on OCI image references.
func ValidateImage(image string) error {
	clean := strings.TrimSpace(image)
	if clean == "" {
		return sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "execution.image must not be empty")
	}
	if strings.Contains(clean, "..") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must not contain '..'", image)
	}
	if strings.ContainsAny(clean, " \t\r\n") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must not contain whitespace", image)
	}
	if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, ".") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must be an OCI image reference", image)
	}
	if !imagePattern.MatchString(clean) {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q contains invalid characters", image)
	}
	return nil
}

// CreateContainerRequest contains the minimum isolation controls required to start a plugin container.
type CreateContainerRequest struct {
	PluginName       string
	Image            string
	NetworkMode      NetworkMode
	MemoryLimitBytes int64
	GRPCPort         int
}

// Engine abstracts container create/start/stop/remove operations.
type Engine interface {
	Create(ctx context.Context, req CreateContainerRequest) (string, error)
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string, timeout time.Duration) error
	Remove(ctx context.Context, id string) error
}

// Runtime manages lifecycle for container-tier plugin instances.
type Runtime struct {
	engine Engine

	mu           sync.Mutex
	stopTimeouts map[string]time.Duration
}

// ContainerInstance is an active plugin container.
type ContainerInstance struct {
	ID       string
	Endpoint string
}

// NewRuntime creates a lifecycle runtime backed by the given container engine.
func NewRuntime(engine Engine) *Runtime {
	return &Runtime{
		engine:       engine,
		stopTimeouts: make(map[string]time.Duration),
	}
}

// NewDefaultRuntime returns a runtime backed by a Docker-compatible OCI engine.
func NewDefaultRuntime() *Runtime {
	return NewRuntime(NewDockerEngine())
}

// Start creates and starts a plugin container with configured isolation settings.
func (r *Runtime) Start(ctx context.Context, cfg ContainerConfig) (*ContainerInstance, error) {
	if r.engine == nil {
		return nil, sigilerr.New(sigilerr.CodePluginRuntimeStartFailure, "container runtime engine is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.NetworkMode == NetworkNone {
		return nil, sigilerr.New(sigilerr.CodePluginRuntimeConfigInvalid,
			"container runtime: NetworkNone is not supported for gRPC plugins; use NetworkRestricted or NetworkHost")
	}

	containerID, err := r.engine.Create(ctx, CreateContainerRequest{
		PluginName:       cfg.PluginName,
		Image:            cfg.Image,
		NetworkMode:      cfg.NetworkMode,
		MemoryLimitBytes: cfg.MemoryLimitBytes,
		GRPCPort:         cfg.GRPCPort,
	})
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"creating container for plugin %s", cfg.PluginName)
	}

	if err := r.engine.Start(ctx, containerID); err != nil {
		_ = r.engine.Remove(ctx, containerID)
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure,
			"starting container %s for plugin %s", containerID, cfg.PluginName)
	}

	r.mu.Lock()
	r.stopTimeouts[containerID] = cfg.StopTimeout
	r.mu.Unlock()

	return &ContainerInstance{
		ID:       containerID,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", cfg.GRPCPort),
	}, nil
}

// Stop gracefully stops and removes a plugin container.
func (r *Runtime) Stop(ctx context.Context, id string) error {
	if r.engine == nil {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container runtime engine is nil")
	}
	if strings.TrimSpace(id) == "" {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container id must not be empty")
	}

	timeout := DefaultStopTimeout
	r.mu.Lock()
	if configuredTimeout, ok := r.stopTimeouts[id]; ok {
		timeout = configuredTimeout
	}
	r.mu.Unlock()

	if err := r.engine.Stop(ctx, id, timeout); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure, "stopping container %s", id)
	}

	if err := r.engine.Remove(ctx, id); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure, "removing container %s", id)
	}

	r.mu.Lock()
	delete(r.stopTimeouts, id)
	r.mu.Unlock()

	return nil
}

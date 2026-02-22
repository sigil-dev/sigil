// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execCommandRunner struct{}

func (r execCommandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		return "", sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure,
			"running %s %s: %s", name, strings.Join(args, " "), trimmed)
	}
	return trimmed, nil
}

// OCIEngine is a minimal runnable engine backed by an OCI-compatible runtime CLI.
type OCIEngine struct {
	runtimeBinary string
	runner        commandRunner
}

// NewOCIEngine creates an OCI engine using the provided runtime binary.
func NewOCIEngine(runtimeBinary string) *OCIEngine {
	return newOCIEngineWithRunner(runtimeBinary, execCommandRunner{})
}

// NewDockerEngine creates an OCI engine using the Docker CLI.
func NewDockerEngine() *OCIEngine {
	return NewOCIEngine("docker")
}

func newOCIEngineWithRunner(runtimeBinary string, runner commandRunner) *OCIEngine {
	bin := strings.TrimSpace(runtimeBinary)
	if bin == "" {
		bin = "docker"
	}
	if runner == nil {
		runner = execCommandRunner{}
	}
	return &OCIEngine{
		runtimeBinary: bin,
		runner:        runner,
	}
}

// Create creates a container with baseline isolation flags applied.
func (e *OCIEngine) Create(ctx context.Context, req CreateContainerRequest) (string, error) {
	if err := validateCreateRequest(req); err != nil {
		return "", err
	}

	args := []string{
		"create",
		"--detach",
		"--name", containerName(req.PluginName),
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", strconv.FormatInt(req.MemoryLimitBytes, 10),
		"--network", networkArg(req.NetworkMode),
	}
	if req.NetworkMode == NetworkRestricted {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", req.GRPCPort, req.GRPCPort))
	}
	args = append(args, req.Image)

	containerID, err := e.runner.Run(ctx, e.runtimeBinary, args...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(containerID) == "" {
		return "", sigilerr.New(sigilerr.CodePluginRuntimeStartFailure, "container runtime returned empty container id")
	}

	return containerID, nil
}

// Start starts a previously created container.
func (e *OCIEngine) Start(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container id must not be empty")
	}
	_, err := e.runner.Run(ctx, e.runtimeBinary, "start", id)
	return err
}

// Stop gracefully stops a running container.
func (e *OCIEngine) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if strings.TrimSpace(id) == "" {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container id must not be empty")
	}
	seconds := int(timeout / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	_, err := e.runner.Run(ctx, e.runtimeBinary, "stop", "--time", strconv.Itoa(seconds), id)
	return err
}

// Remove force-removes a container.
func (e *OCIEngine) Remove(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container id must not be empty")
	}
	_, err := e.runner.Run(ctx, e.runtimeBinary, "rm", "--force", id)
	return err
}

func validateCreateRequest(req CreateContainerRequest) error {
	if strings.TrimSpace(req.PluginName) == "" {
		return sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "plugin name must not be empty")
	}
	if err := ValidateImage(req.Image); err != nil {
		return err
	}
	if !validNetworkModes[req.NetworkMode] {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"network mode must be one of [none, restricted, host], got %q", req.NetworkMode)
	}
	if req.MemoryLimitBytes <= 0 {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"memory limit must be > 0, got %d", req.MemoryLimitBytes)
	}
	if req.GRPCPort <= 0 || req.GRPCPort > 65535 {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"grpc port must be in range 1..65535, got %d", req.GRPCPort)
	}
	return nil
}

func networkArg(mode NetworkMode) string {
	switch mode {
	case NetworkNone:
		return "none"
	case NetworkHost:
		return "host"
	default:
		return "bridge"
	}
}

func containerName(pluginName string) string {
	name := strings.ToLower(strings.TrimSpace(pluginName))
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, " ", "-")
	return "sigil-" + name + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

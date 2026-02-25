// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
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
// The caller is responsible for validating the request fields (e.g., via ContainerConfig.Validate).
// NetworkNone is rejected: a container with no network cannot expose the gRPC endpoint.
func (e *OCIEngine) Create(ctx context.Context, req CreateContainerRequest) (string, error) {
	if req.NetworkMode == NetworkNone {
		return "", sigilerr.New(sigilerr.CodePluginManifestValidateInvalid,
			"NetworkNone is not supported: container must be reachable via gRPC")
	}
	sanitized, err := containerName(req.PluginName)
	if err != nil {
		return "", err
	}
	networkFlag, err := networkArg(req.NetworkMode)
	if err != nil {
		return "", err
	}
	args := []string{
		"create",
		"--name", sanitized,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", strconv.FormatInt(req.MemoryLimitBytes, 10),
		"--network", networkFlag,
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
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeStartFailure, "starting container %s", id)
	}
	return nil
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
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure, "stopping container %s", id)
	}
	return nil
}

// Remove force-removes a container.
func (e *OCIEngine) Remove(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return sigilerr.New(sigilerr.CodePluginRuntimeCallFailure, "container id must not be empty")
	}
	_, err := e.runner.Run(ctx, e.runtimeBinary, "rm", "--force", id)
	if err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodePluginRuntimeCallFailure, "removing container %s", id)
	}
	return nil
}

func networkArg(mode NetworkMode) (string, error) {
	switch mode {
	case NetworkNone:
		return "none", nil
	case NetworkHost:
		return "host", nil
	case NetworkRestricted:
		return "bridge", nil
	default:
		return "", sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"unrecognized container network mode: %q", mode)
	}
}

// invalidContainerNameChars matches characters not allowed in Docker container names.
// Docker names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*.
var invalidContainerNameChars = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

// alphanumericPattern matches strings that contain at least one alphanumeric character.
var alphanumericPattern = regexp.MustCompile(`[a-zA-Z0-9]`)

// containerName returns the sanitized Docker container name for a plugin.
// It lowercases, trims, and replaces invalid characters with hyphens, then
// validates that the result contains at least one alphanumeric character.
func containerName(pluginName string) (string, error) {
	if strings.TrimSpace(pluginName) == "" {
		return "", sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "plugin name must not be blank")
	}
	// Sanitize the plugin name segment first (without the "sigil-" prefix) so that
	// the alphanumeric check is not trivially satisfied by the prefix itself.
	nameSegment := invalidContainerNameChars.ReplaceAllString(
		strings.ToLower(strings.TrimSpace(pluginName)), "-")
	if !alphanumericPattern.MatchString(nameSegment) {
		return "", sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"plugin name %q produces invalid container name after sanitization", pluginName)
	}
	return "sigil-" + nameSegment, nil
}

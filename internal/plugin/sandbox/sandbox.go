// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sigil-dev/sigil/internal/plugin"
)

var (
	bwrapPath       = "bwrap"
	sandboxExecPath = "sandbox-exec"
)

func init() {
	if p, err := exec.LookPath("bwrap"); err == nil {
		bwrapPath = p
	}
	if p, err := exec.LookPath("sandbox-exec"); err == nil {
		sandboxExecPath = p
	}
}

func GenerateArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	if manifest.Execution.Tier != plugin.TierProcess {
		return nil, nil
	}

	switch runtime.GOOS {
	case "linux":
		return generateBwrapArgs(manifest, binaryPath)
	case "darwin":
		return generateSandboxExecArgs(manifest, binaryPath)
	default:
		return nil, fmt.Errorf("sandbox not supported on %s", runtime.GOOS)
	}
}

func generateBwrapArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	args := []string{bwrapPath}

	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind", "/lib64", "/lib64",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/etc", "/etc",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)

	sb := manifest.Execution.Sandbox

	for _, path := range sb.Filesystem.WriteAllow {
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			args = append(args, "--bind", dir, dir)
		} else {
			args = append(args, "--bind", expanded, expanded)
		}
	}

	for _, path := range sb.Filesystem.ReadDeny {
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			args = append(args, "--tmpfs", dir)
		} else {
			args = append(args, "--tmpfs", expanded)
		}
	}

	if sb.Network.Proxy || len(sb.Network.Allow) > 0 {
		args = append(args, "--unshare-net")
	}

	args = append(args, "--", binaryPath)

	return args, nil
}

func generateSandboxExecArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	profile := generateSeatbeltProfile(manifest)

	args := []string{sandboxExecPath, "-p", profile, "--", binaryPath}

	return args, nil
}

func generateSeatbeltProfile(manifest *plugin.Manifest) string {
	var rules []string

	rules = append(rules, "(version 1)")
	rules = append(rules, "(deny default)")

	rules = append(rules, "(allow process-exec (path \"/usr/bin\" \"/bin\" \"/usr/lib\" \"/lib\"))")
	rules = append(rules, "(allow file-read* (path \"/usr\" \"/lib\" \"/bin\" \"/System\" \"/etc\"))")

	sb := manifest.Execution.Sandbox

	for _, path := range sb.Filesystem.WriteAllow {
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			rules = append(rules, fmt.Sprintf("(allow file-write* (subpath \"%s\"))", dir))
		} else {
			rules = append(rules, fmt.Sprintf("(allow file-write* (path \"%s\"))", expanded))
		}
	}

	for _, path := range sb.Filesystem.ReadDeny {
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			rules = append(rules, fmt.Sprintf("(deny file-read* (subpath \"%s\"))", dir))
		} else {
			rules = append(rules, fmt.Sprintf("(deny file-read* (path \"%s\"))", expanded))
		}
	}

	if len(sb.Network.Allow) > 0 {
		rules = append(rules, "(allow network* (remote tcp))")
	} else {
		rules = append(rules, "(deny network*)")
	}

	return strings.Join(rules, " ")
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	return path
}

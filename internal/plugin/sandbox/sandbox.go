// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/sigil-dev/sigil/internal/plugin"
)

var (
	bwrapPath       = "bwrap"
	sandboxExecPath = "sandbox-exec"

	// targetOS allows tests to override the OS for cross-platform testing.
	targetOS = runtime.GOOS

	// checkDirExists allows tests to stub filesystem existence checks.
	checkDirExists = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
)

// dangerousPathChars matches characters that enable Seatbelt profile injection
// or bwrap argument confusion: quotes, parens, backslash, semicolons, control chars.
var dangerousPathChars = regexp.MustCompile(`["\\();\x00-\x1f]`)

func init() {
	if p, err := exec.LookPath("bwrap"); err == nil {
		bwrapPath = p
	}
	if p, err := exec.LookPath("sandbox-exec"); err == nil {
		sandboxExecPath = p
	}
}

// validateSandboxPath rejects paths containing characters that could be used
// for injection in Seatbelt profiles or bwrap argument confusion.
func validateSandboxPath(path string) error {
	if path == "" {
		return fmt.Errorf("invalid path: must not be empty")
	}
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("invalid path %q: must not start with dash", path)
	}
	if dangerousPathChars.MatchString(path) {
		return fmt.Errorf("invalid path %q: contains disallowed characters", path)
	}
	return nil
}

func GenerateArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	if manifest.Execution.Tier != plugin.TierProcess {
		return nil, nil
	}

	switch targetOS {
	case "linux":
		return generateBwrapArgs(manifest, binaryPath)
	case "darwin":
		return generateSandboxExecArgs(manifest, binaryPath)
	default:
		return nil, fmt.Errorf("sandbox not supported on %s", targetOS)
	}
}

func generateBwrapArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	args := []string{bwrapPath}

	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
	)

	// Only mount /lib64 if it exists (absent on Alpine/musl systems).
	if checkDirExists("/lib64") {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}

	args = append(args,
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/etc", "/etc",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)

	sb := manifest.Execution.Sandbox

	for _, path := range sb.Filesystem.WriteAllow {
		if err := validateSandboxPath(path); err != nil {
			return nil, err
		}
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			args = append(args, "--bind", dir, dir)
		} else {
			args = append(args, "--bind", expanded, expanded)
		}
	}

	for _, path := range sb.Filesystem.ReadDeny {
		if err := validateSandboxPath(path); err != nil {
			return nil, err
		}
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
	profile, err := generateSeatbeltProfile(manifest)
	if err != nil {
		return nil, err
	}

	args := []string{sandboxExecPath, "-p", profile, "--", binaryPath}

	return args, nil
}

func generateSeatbeltProfile(manifest *plugin.Manifest) (string, error) {
	var rules []string

	rules = append(rules, "(version 1)")
	rules = append(rules, "(deny default)")

	// System exec paths — each (subpath ...) gets its own rule (Seatbelt
	// path/subpath filters accept exactly one argument).
	for _, p := range []string{"/usr/bin", "/bin", "/usr/lib", "/lib"} {
		rules = append(rules, fmt.Sprintf(`(allow process-exec (subpath "%s"))`, p))
	}

	// System read paths — subpath for recursive directory access.
	for _, p := range []string{"/usr", "/lib", "/bin", "/System", "/etc"} {
		rules = append(rules, fmt.Sprintf(`(allow file-read* (subpath "%s"))`, p))
	}

	sb := manifest.Execution.Sandbox

	for _, path := range sb.Filesystem.WriteAllow {
		if err := validateSandboxPath(path); err != nil {
			return "", err
		}
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			rules = append(rules, fmt.Sprintf(`(allow file-write* (subpath "%s"))`, dir))
		} else {
			rules = append(rules, fmt.Sprintf(`(allow file-write* (path "%s"))`, expanded))
		}
	}

	for _, path := range sb.Filesystem.ReadDeny {
		if err := validateSandboxPath(path); err != nil {
			return "", err
		}
		expanded := expandPath(path)
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			rules = append(rules, fmt.Sprintf(`(deny file-read* (subpath "%s"))`, dir))
		} else {
			rules = append(rules, fmt.Sprintf(`(deny file-read* (path "%s"))`, expanded))
		}
	}

	if len(sb.Network.Allow) > 0 {
		// Generate per-entry port-specific rules instead of blanket TCP allow.
		for _, entry := range sb.Network.Allow {
			_, port, err := net.SplitHostPort(entry)
			if err != nil {
				return "", fmt.Errorf("invalid network allow entry %q: expected host:port format", entry)
			}
			p, err := strconv.Atoi(port)
			if err != nil {
				return "", fmt.Errorf("invalid port in network allow entry %q", entry)
			}
			if p < 1 || p > 65535 {
				return "", fmt.Errorf("port %d out of range (1-65535) in network allow entry %q", p, entry)
			}
			rules = append(rules, fmt.Sprintf(`(allow network-outbound (remote tcp "*:%s"))`, port))
		}
	} else {
		rules = append(rules, "(deny network*)")
	}

	return strings.Join(rules, " "), nil
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

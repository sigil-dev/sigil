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
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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
		return sigilerr.New(sigilerr.CodePluginSandboxPathInvalid, "invalid path: must not be empty")
	}
	if strings.HasPrefix(path, "-") {
		return sigilerr.Errorf(sigilerr.CodePluginSandboxPathInvalid, "invalid path %q: must not start with dash", path)
	}
	if dangerousPathChars.MatchString(path) {
		return sigilerr.Errorf(sigilerr.CodePluginSandboxPathInvalid, "invalid path %q: contains disallowed characters", path)
	}
	return nil
}

func GenerateArgs(manifest *plugin.Manifest, binaryPath string) ([]string, error) {
	// Item 5: Container tier returns a descriptive error instead of silent nil.
	if manifest.Execution.Tier == plugin.TierContainer {
		return nil, sigilerr.New(sigilerr.CodePluginSandboxUnsupported, "sandbox for container tier not yet implemented")
	}

	if manifest.Execution.Tier != plugin.TierProcess {
		return nil, nil
	}

	// Reject empty or whitespace-only binaryPath.
	if strings.TrimSpace(binaryPath) == "" {
		return nil, sigilerr.New(sigilerr.CodePluginSandboxPathInvalid, "binaryPath must not be empty or whitespace-only")
	}
	// Validate binaryPath against injection characters (same rules as manifest paths).
	if err := validateSandboxPath(binaryPath); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginSandboxPathInvalid, "invalid binaryPath")
	}

	switch targetOS {
	case "linux":
		return generateBwrapArgs(manifest, binaryPath)
	case "darwin":
		return generateSandboxExecArgs(manifest, binaryPath)
	default:
		return nil, sigilerr.Errorf(sigilerr.CodePluginSandboxUnsupported, "sandbox not supported on %s", targetOS)
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
		"--unshare-pid",
	)

	sb := manifest.Execution.Sandbox

	for _, path := range sb.Filesystem.WriteAllow {
		if err := validateSandboxPath(path); err != nil {
			return nil, err
		}
		expanded, err := expandPath(path)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			args = append(args, "--bind", dir, dir)
		} else {
			args = append(args, "--bind", expanded, expanded)
		}
	}

	// ReadDeny is implemented by mounting a tmpfs over the denied path rather
	// than using permission-denied semantics. This design choice ensures the
	// path exists (preventing ENOENT errors that could leak information about
	// filesystem layout) while making the original content inaccessible. The
	// tmpfs overlay is empty and writable, which is a stronger guarantee than
	// a permission bit change that could be circumvented by a privileged process.
	for _, path := range sb.Filesystem.ReadDeny {
		if err := validateSandboxPath(path); err != nil {
			return nil, err
		}
		expanded, err := expandPath(path)
		if err != nil {
			return nil, err
		}
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

	// Write the Seatbelt profile to a temp file and reference it via -f.
	// Using -f instead of inline -p avoids shell argument length limits and
	// reduces risk of argument injection through profile content.
	//
	// NOTE: The temp file persists after this function returns because
	// sandbox-exec needs to read it at process start. The caller is
	// responsible for removing args[2] (the profile path) after the
	// sandboxed process has started. Files live in os.TempDir() and
	// will be cleaned up on reboot if not removed explicitly.
	f, err := os.CreateTemp("", "sigil-seatbelt-*.sb")
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginSandboxSetupFailure, "creating seatbelt profile temp file")
	}

	if _, err := f.WriteString(profile); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginSandboxSetupFailure, "writing seatbelt profile")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return nil, sigilerr.Wrapf(err, sigilerr.CodePluginSandboxSetupFailure, "closing seatbelt profile temp file")
	}

	args := []string{sandboxExecPath, "-f", f.Name(), "--", binaryPath}

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
		expanded, err := expandPath(path)
		if err != nil {
			return "", err
		}
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
		expanded, err := expandPath(path)
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(expanded, "/*") {
			dir := strings.TrimSuffix(expanded, "/*")
			rules = append(rules, fmt.Sprintf(`(deny file-read* (subpath "%s"))`, dir))
		} else {
			rules = append(rules, fmt.Sprintf(`(deny file-read* (path "%s"))`, expanded))
		}
	}

	if len(sb.Network.Allow) > 0 {
		// Generate per-entry port-specific rules instead of blanket TCP allow.
		// LIMITATION: Seatbelt's network-outbound filter does NOT support hostname
		// filtering. The rule (allow network-outbound (remote tcp "*:443")) allows
		// connections to ANY host on port 443, not just the manifest-specified host.
		// This is a platform limitation of SBPL (Sandbox Profile Language).
		// The manifest's Proxy field anticipates a future userspace proxy solution
		// that would enforce per-host restrictions at the application layer.
		for _, entry := range sb.Network.Allow {
			_, port, err := net.SplitHostPort(entry)
			if err != nil {
				return "", sigilerr.Errorf(sigilerr.CodePluginSandboxNetworkInvalid, "invalid network allow entry %q: expected host:port format", entry)
			}
			p, err := strconv.Atoi(port)
			if err != nil {
				return "", sigilerr.Errorf(sigilerr.CodePluginSandboxNetworkInvalid, "invalid port in network allow entry %q", entry)
			}
			if p < 1 || p > 65535 {
				return "", sigilerr.Errorf(sigilerr.CodePluginSandboxNetworkInvalid, "port %d out of range (1-65535) in network allow entry %q", p, entry)
			}
			rules = append(rules, fmt.Sprintf(`(allow network-outbound (remote tcp "*:%s"))`, port))
		}
	} else {
		rules = append(rules, "(deny network*)")
	}

	return strings.Join(rules, " "), nil
}

func expandPath(path string) (string, error) {
	// Only expand ~/foo syntax (tilde followed by slash).
	// Do NOT expand ~user/foo syntax (tilde followed by username),
	// since the manifest schema doesn't document ~user support and
	// correctly resolving it would require os/user.Lookup.
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", sigilerr.Wrapf(err, sigilerr.CodePluginSandboxSetupFailure, "expanding %q: home directory unavailable", path)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

// TODO(seccomp): Implement a basic BPF syscall allow-list for process-tier
// plugins on Linux. This would restrict the syscall surface beyond what bwrap
// namespace isolation provides. A minimal allow-list should cover: read, write,
// openat, close, mmap, mprotect, brk, rt_sigaction, rt_sigprocmask, exit_group,
// and the gRPC-required network syscalls (socket, connect, sendto, recvfrom).
// Tracking issue should be created before this is implemented due to the
// complexity of maintaining per-architecture BPF filter compatibility.

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox

import (
	"os"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Seatbelt path injection ---

func TestSeatbeltProfile_PathInjection_WriteAllow(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "reject double-quote injection",
			path:    `/tmp") (allow default) (deny file-read* (path "/fake`,
			wantErr: true,
		},
		{
			name:    "reject parenthesis in path",
			path:    `/tmp/(allow default)/data`,
			wantErr: true,
		},
		{
			name:    "reject backslash in path",
			path:    `/tmp\escape`,
			wantErr: true,
		},
		{
			name:    "accept clean absolute path",
			path:    "/data/plugins/self",
			wantErr: false,
		},
		{
			name:    "accept glob suffix",
			path:    "/data/plugins/self/*",
			wantErr: false,
		},
		{
			name:    "accept tilde home path",
			path:    "~/.config/plugin",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &plugin.Manifest{
				Execution: plugin.ExecutionConfig{
					Sandbox: plugin.SandboxConfig{
						Filesystem: plugin.FilesystemSandbox{
							WriteAllow: []string{tt.path},
						},
					},
				},
			}
			profile, err := generateSeatbeltProfile(manifest)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotContains(t, profile, "(allow default)")
			}
		})
	}
}

func TestSeatbeltProfile_PathInjection_ReadDeny(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{
				Filesystem: plugin.FilesystemSandbox{
					ReadDeny: []string{`/etc") (allow default) (path "/fake`},
				},
			},
		},
	}
	_, err := generateSeatbeltProfile(manifest)
	require.Error(t, err)
}

// --- Seatbelt single-path-per-filter ---

func TestSeatbeltProfile_SinglePathPerFilter(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{},
		},
	}
	profile, err := generateSeatbeltProfile(manifest)
	require.NoError(t, err)

	// Old bug: (path "/usr/bin" "/bin" "/usr/lib" "/lib") — multi-path invalid syntax
	assert.NotContains(t, profile, `"/usr/bin" "/bin"`)
	assert.NotContains(t, profile, `"/usr" "/lib"`)

	// Each system directory must appear in its own filter using subpath
	assert.Contains(t, profile, `(allow process-exec (subpath "/usr/bin"))`)
	assert.Contains(t, profile, `(allow process-exec (subpath "/bin"))`)
	assert.Contains(t, profile, `(allow file-read* (subpath "/usr"))`)
	assert.Contains(t, profile, `(allow file-read* (subpath "/bin"))`)
}

// --- Network host:port enforcement ---

func TestSeatbeltProfile_NetworkRespectHostPort(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{
				Network: plugin.NetworkSandbox{
					Allow: []string{"api.telegram.org:443", "example.com:8080"},
				},
			},
		},
	}
	profile, err := generateSeatbeltProfile(manifest)
	require.NoError(t, err)

	// Must NOT have blanket TCP allow
	assert.NotContains(t, profile, "(allow network* (remote tcp))")

	// Must have port-specific rules with correct syntax
	assert.Contains(t, profile, `(allow network-outbound (remote tcp "*:443"))`)
	assert.Contains(t, profile, `(allow network-outbound (remote tcp "*:8080"))`)
}

func TestSeatbeltProfile_NetworkDenyWhenEmpty(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{
				Network: plugin.NetworkSandbox{},
			},
		},
	}
	profile, err := generateSeatbeltProfile(manifest)
	require.NoError(t, err)
	assert.Contains(t, profile, "(deny network*)")
	assert.NotContains(t, profile, "(allow network")
}

func TestSeatbeltProfile_NetworkInvalidPort(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{
				Network: plugin.NetworkSandbox{
					Allow: []string{"host:notaport"},
				},
			},
		},
	}
	_, err := generateSeatbeltProfile(manifest)
	require.Error(t, err)
}

func TestSeatbeltProfile_NetworkNoPort(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{
				Network: plugin.NetworkSandbox{
					Allow: []string{"just-a-host"},
				},
			},
		},
	}
	_, err := generateSeatbeltProfile(manifest)
	require.Error(t, err)
}

func TestSeatbeltProfile_NetworkPortOutOfRange(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"port zero", "host:0"},
		{"port negative", "host:-1"},
		{"port too high", "host:99999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &plugin.Manifest{
				Execution: plugin.ExecutionConfig{
					Sandbox: plugin.SandboxConfig{
						Network: plugin.NetworkSandbox{
							Allow: []string{tt.entry},
						},
					},
				},
			}
			_, err := generateSeatbeltProfile(manifest)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "out of range")
		})
	}
}

// --- Content structure ---

func TestSeatbeltProfile_ContentStructure(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Sandbox: plugin.SandboxConfig{},
		},
	}
	profile, err := generateSeatbeltProfile(manifest)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(profile, "(version 1) (deny default)"),
		"profile must start with version and deny default, got: %s", profile)
}

// --- Path validation ---

func TestValidateSandboxPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid absolute", "/usr/bin", false},
		{"valid with glob", "/data/*", false},
		{"valid tilde", "~/.config", false},
		{"valid with dots", "/usr/lib/x86_64-linux-gnu", false},
		{"valid with hyphens", "/data/my-plugin", false},
		{"valid with underscores", "/data/my_plugin", false},
		{"reject double-quote", `/path/with"quote`, true},
		{"reject open paren", "/path/with(paren", true},
		{"reject close paren", "/path/with)paren", true},
		{"reject backslash", `/path/with\back`, true},
		{"reject semicolon", "/path/with;semi", true},
		{"reject newline", "/path/with\nnewline", true},
		{"reject dash-dash prefix", "--dev-bind-try", true},
		{"reject single-dash prefix", "-flag", true},
		{"reject empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSandboxPath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- OS and config edge cases ---

func TestGenerateArgs_UnsupportedOS(t *testing.T) {
	orig := targetOS
	defer func() { targetOS = orig }()
	targetOS = "plan9"

	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierProcess,
		},
	}
	_, err := GenerateArgs(manifest, "/path/to/binary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plan9")
}

func TestGenerateArgs_EmptySandboxConfig(t *testing.T) {
	orig := targetOS
	defer func() { targetOS = orig }()

	for _, osName := range []string{"linux", "darwin"} {
		t.Run(osName, func(t *testing.T) {
			targetOS = osName
			manifest := &plugin.Manifest{
				Execution: plugin.ExecutionConfig{
					Tier:    plugin.TierProcess,
					Sandbox: plugin.SandboxConfig{},
				},
			}
			args, err := GenerateArgs(manifest, "/path/to/binary")
			require.NoError(t, err)
			assert.NotEmpty(t, args)
		})
	}
}

// --- bwrap conditional /lib64 ---

func TestBwrapArgs_ConditionalLib64(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Tier:    plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{},
		},
	}

	origCheck := checkDirExists
	defer func() { checkDirExists = origCheck }()

	// When /lib64 doesn't exist, it must not appear in args
	checkDirExists = func(path string) bool { return path != "/lib64" }
	args, err := generateBwrapArgs(manifest, "/path/to/binary")
	require.NoError(t, err)
	for _, arg := range args {
		assert.NotEqual(t, "/lib64", arg,
			"/lib64 should not be in args when directory doesn't exist")
	}

	// When /lib64 exists, it must appear in args
	checkDirExists = func(_ string) bool { return true }
	args, err = generateBwrapArgs(manifest, "/path/to/binary")
	require.NoError(t, err)
	assert.Contains(t, args, "/lib64")
}

// --- bwrap path validation ---

func TestBwrapArgs_RejectDashDashPaths(t *testing.T) {
	tests := []struct {
		name       string
		writeAllow []string
		readDeny   []string
		wantErr    bool
	}{
		{
			name:       "reject --prefix in write allow",
			writeAllow: []string{"--dev-bind-try"},
			wantErr:    true,
		},
		{
			name:     "reject --prefix in read deny",
			readDeny: []string{"--tmpfs"},
			wantErr:  true,
		},
		{
			name:       "accept valid paths",
			writeAllow: []string{"/data/plugins"},
			readDeny:   []string{"/etc/shadow"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &plugin.Manifest{
				Execution: plugin.ExecutionConfig{
					Tier: plugin.TierProcess,
					Sandbox: plugin.SandboxConfig{
						Filesystem: plugin.FilesystemSandbox{
							WriteAllow: tt.writeAllow,
							ReadDeny:   tt.readDeny,
						},
					},
				},
			}
			_, err := generateBwrapArgs(manifest, "/path/to/binary")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- Item 1: --unshare-pid in bwrap args ---

func TestBwrapArgs_UnsharesPID(t *testing.T) {
	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Tier:    plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{},
		},
	}

	args, err := generateBwrapArgs(manifest, "/path/to/binary")
	require.NoError(t, err)
	assert.Contains(t, args, "--unshare-pid",
		"bwrap args must include --unshare-pid for PID namespace isolation")
}

// --- Item 2: expandPath warns on UserHomeDir failure ---

func TestExpandPath_ErrorOnHomeDirFailure(t *testing.T) {
	// Save and unset HOME to make os.UserHomeDir fail.
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { _ = os.Setenv("HOME", origHome) })
	_ = os.Unsetenv("HOME")
	// Also unset platform-specific fallbacks.
	if v, ok := os.LookupEnv("USERPROFILE"); ok {
		_ = os.Unsetenv("USERPROFILE")
		t.Cleanup(func() { _ = os.Setenv("USERPROFILE", v) })
	}

	_, err := expandPath("~/some/path")
	require.Error(t, err, "should return error when home dir unavailable")
	assert.Contains(t, err.Error(), "home directory unavailable")
}

// --- Item 3: binaryPath validation ---

func TestGenerateArgs_BinaryPathValidation(t *testing.T) {
	tests := []struct {
		name       string
		binaryPath string
		wantErr    string
	}{
		{
			name:       "empty binary path",
			binaryPath: "",
			wantErr:    "binaryPath must not be empty",
		},
		{
			name:       "whitespace-only binary path",
			binaryPath: "   ",
			wantErr:    "binaryPath must not be empty",
		},
		{
			name:       "tab-only binary path",
			binaryPath: "\t\n",
			wantErr:    "binaryPath must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origOS := targetOS
			defer func() { targetOS = origOS }()

			for _, osName := range []string{"linux", "darwin"} {
				targetOS = osName
				manifest := &plugin.Manifest{
					Execution: plugin.ExecutionConfig{
						Tier:    plugin.TierProcess,
						Sandbox: plugin.SandboxConfig{},
					},
				}
				_, err := GenerateArgs(manifest, tt.binaryPath)
				require.Error(t, err, "OS=%s binaryPath=%q should error", osName, tt.binaryPath)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// --- binaryPath injection validation ---

func TestGenerateArgs_BinaryPathInjection(t *testing.T) {
	tests := []struct {
		name       string
		binaryPath string
	}{
		{"double-quote injection", `/usr/bin/plugin"--dev-bind /etc /etc`},
		{"semicolon injection", `/usr/bin/plugin;rm -rf /`},
		{"backslash injection", `/usr/bin/plugin\n--bind / /`},
		{"dash prefix", "--dev-bind-try"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origOS := targetOS
			defer func() { targetOS = origOS }()
			targetOS = "linux"

			manifest := &plugin.Manifest{
				Execution: plugin.ExecutionConfig{
					Tier:    plugin.TierProcess,
					Sandbox: plugin.SandboxConfig{},
				},
			}
			_, err := GenerateArgs(manifest, tt.binaryPath)
			require.Error(t, err, "binaryPath %q should be rejected", tt.binaryPath)
			assert.Contains(t, err.Error(), "invalid binaryPath")
		})
	}
}

// --- Item 4: Seatbelt profile written to temp file, referenced via -f ---

func TestSeatbeltArgs_UsesFileBasedProfile(t *testing.T) {
	origOS := targetOS
	defer func() { targetOS = origOS }()
	targetOS = "darwin"

	manifest := &plugin.Manifest{
		Execution: plugin.ExecutionConfig{
			Tier:    plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{},
		},
	}

	args, err := GenerateArgs(manifest, "/usr/bin/plugin-binary")
	require.NoError(t, err)

	// Must use -f flag, not -p flag
	assert.Contains(t, args, "-f",
		"sandbox-exec args must use -f for file-based profile")
	assert.NotContains(t, args, "-p",
		"sandbox-exec args must not use -p for inline profile")

	// Find the index of -f and verify the file exists and contains profile content.
	for i, arg := range args {
		if arg == "-f" {
			require.Greater(t, len(args), i+1, "must have file path after -f")
			profilePath := args[i+1]
			content, err := os.ReadFile(profilePath)
			require.NoError(t, err, "profile temp file must be readable")
			assert.Contains(t, string(content), "(version 1)")
			assert.Contains(t, string(content), "(deny default)")
			// Clean up the temp file
			_ = os.Remove(profilePath)
			return
		}
	}
	t.Fatal("-f flag found but no file path followed")
}

// --- Item 5: Container tier returns descriptive error ---

func TestGenerateArgs_ContainerTierReturnsError(t *testing.T) {
	manifest := &plugin.Manifest{
		Name: "test-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierContainer,
		},
	}

	_, err := GenerateArgs(manifest, "/path/to/binary")
	require.Error(t, err, "container tier must return an error")
	assert.Contains(t, err.Error(), "container")
	assert.Contains(t, err.Error(), "not yet implemented")
}

// --- ~user path expansion ---

func TestExpandPath_TildeUserSyntax(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string // If empty, expect path unchanged via home expansion
	}{
		{
			name:     "tilde-slash expands to home",
			path:     "~/config",
			expected: "", // Will be user's home + "/config"
		},
		{
			name:     "bare tilde is returned unchanged",
			path:     "~",
			expected: "~",
		},
		{
			name:     "tilde-user is returned unchanged",
			path:     "~otheruser/data",
			expected: "~otheruser/data",
		},
		{
			name:     "tilde-user with multiple segments",
			path:     "~alice/documents/projects",
			expected: "~alice/documents/projects",
		},
		{
			name:     "absolute path unchanged",
			path:     "/usr/bin",
			expected: "/usr/bin",
		},
		{
			name:     "relative path unchanged",
			path:     "data/files",
			expected: "data/files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandPath(tt.path)
			require.NoError(t, err)

			if tt.expected == "" && strings.HasPrefix(tt.path, "~/") {
				// For ~/foo, expect expansion to $HOME/foo
				home, err := os.UserHomeDir()
				require.NoError(t, err)
				expected := strings.Replace(tt.path, "~", home, 1)
				assert.Equal(t, expected, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

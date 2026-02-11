// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox

import (
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

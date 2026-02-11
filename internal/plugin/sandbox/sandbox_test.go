// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox_test

import (
	"runtime"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/plugin/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSandboxArgs_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	manifest := &plugin.Manifest{
		Name: "test-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{
				Filesystem: plugin.FilesystemSandbox{
					WriteAllow: []string{"/data/plugins/self/*"},
					ReadDeny:   []string{"/etc/shadow", "~/.ssh/*"},
				},
				Network: plugin.NetworkSandbox{
					Allow: []string{"api.telegram.org:443"},
					Proxy: true,
				},
			},
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/usr/bin/plugin-binary")
	require.NoError(t, err)
	assert.Contains(t, args[0], "bwrap")
	assert.Contains(t, args, "--ro-bind")
}

func TestGenerateSandboxArgs_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	manifest := &plugin.Manifest{
		Name: "test-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{
				Filesystem: plugin.FilesystemSandbox{
					WriteAllow: []string{"/data/plugins/self/*"},
				},
				Network: plugin.NetworkSandbox{
					Allow: []string{"api.telegram.org:443"},
				},
			},
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/usr/bin/plugin-binary")
	require.NoError(t, err)
	assert.Contains(t, args[0], "sandbox-exec")
}

func TestGenerateSandboxArgs_NoSandboxForWasm(t *testing.T) {
	manifest := &plugin.Manifest{
		Name: "wasm-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierWasm,
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/path/to/binary")
	require.NoError(t, err)
	assert.Nil(t, args)
}

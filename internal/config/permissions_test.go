// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

//go:build !windows

package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWarnInsecurePermissions(t *testing.T) {
	tests := []struct {
		name        string
		perm        os.FileMode
		expectWarn  bool
		warnKeyword string
	}{
		{
			name:        "secure 0600",
			perm:        0o600,
			expectWarn:  false,
			warnKeyword: "",
		},
		{
			name:        "secure 0400",
			perm:        0o400,
			expectWarn:  false,
			warnKeyword: "",
		},
		{
			name:        "insecure 0644 (group readable)",
			perm:        0o644,
			expectWarn:  true,
			warnKeyword: "insecure permissions",
		},
		{
			name:        "insecure 0604 (other readable)",
			perm:        0o604,
			expectWarn:  true,
			warnKeyword: "insecure permissions",
		},
		{
			name:        "insecure 0666 (group and other readable)",
			perm:        0o666,
			expectWarn:  true,
			warnKeyword: "insecure permissions",
		},
		{
			name:        "insecure 0640 (group readable)",
			perm:        0o640,
			expectWarn:  true,
			warnKeyword: "insecure permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary config file with specified permissions.
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "sigil.yaml")

			err := os.WriteFile(configPath, []byte("networking:\n  listen: ':8080'\n"), tt.perm)
			require.NoError(t, err, "failed to create test config file")

			// Capture log output to verify warning.
			var buf bytes.Buffer
			oldDefault := slog.Default()
			defer slog.SetDefault(oldDefault)

			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
			slog.SetDefault(slog.New(handler))

			// Call the function under test.
			WarnInsecurePermissions(configPath)

			logOutput := buf.String()

			if tt.expectWarn {
				assert.Contains(t, logOutput, tt.warnKeyword,
					"expected warning keyword %q in log output", tt.warnKeyword)
				assert.Contains(t, logOutput, configPath,
					"expected config path in log output")
				assert.Contains(t, logOutput, "0600",
					"expected recommended permissions in log output")
			} else {
				assert.NotContains(t, logOutput, "insecure permissions",
					"unexpected warning for secure permissions")
			}
		})
	}
}

func TestWarnInsecurePermissions_EmptyPath(t *testing.T) {
	var buf bytes.Buffer
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	// Empty path should be a no-op (no config file loaded).
	WarnInsecurePermissions("")

	logOutput := buf.String()
	assert.Empty(t, logOutput, "expected no log output for empty path")
}

func TestWarnInsecurePermissions_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	// Missing file should log debug message but not warn.
	WarnInsecurePermissions("/nonexistent/path/sigil.yaml")

	logOutput := buf.String()

	// Should log debug but not warn.
	if logOutput != "" {
		assert.True(t, strings.Contains(logOutput, "level=DEBUG") || strings.Contains(logOutput, "could not stat"),
			"expected debug log for missing file, got: %s", logOutput)
		assert.NotContains(t, logOutput, "insecure permissions",
			"should not warn about missing file")
	}
}

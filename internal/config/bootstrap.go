// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package config

import (
	_ "embed"
	"log/slog"
	"os"
	"path/filepath"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

//go:embed sigil.yaml.default
var DefaultConfigYAML []byte

// DefaultConfigPath returns ~/.config/sigil/sigil.yaml.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "sigil", "sigil.yaml"), nil
}

// BootstrapConfig writes the default commented config to path if it does not
// already exist. Returns the path written, or empty string if the file already
// existed or an error occurred (non-fatal — logged and skipped).
func BootstrapConfig() string {
	cfgPath, err := DefaultConfigPath()
	if err != nil {
		slog.Debug("skipping config bootstrap", "error", err)
		return ""
	}

	if _, err := os.Stat(cfgPath); err == nil {
		return "" // already exists
	}

	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Debug("skipping config bootstrap: cannot create directory", "path", dir, "error", err)
		return ""
	}

	if err := os.WriteFile(cfgPath, DefaultConfigYAML, 0o600); err != nil {
		slog.Debug("skipping config bootstrap: cannot write config", "path", cfgPath, "error", err)
		return ""
	}

	slog.Info("created default config", "path", cfgPath)
	return cfgPath
}

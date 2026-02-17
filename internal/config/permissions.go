// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

//go:build !windows

package config

import (
	"io/fs"
	"log/slog"
	"os"
)

// WarnInsecurePermissions checks if the config file has overly permissive
// permissions (group- or world-readable) and logs a warning if so.
// This is a best-effort check — it does not fail startup, but alerts the
// operator that sensitive tokens may be exposed to other users on the system.
func WarnInsecurePermissions(path string) {
	if path == "" {
		// No config file loaded (using defaults only). Nothing to check.
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		// Config file missing or inaccessible. Already logged elsewhere.
		slog.Debug("could not stat config file for permission check", "path", path, "error", err)
		return
	}

	mode := info.Mode()
	perm := mode.Perm()

	// Check if group or world can read the file (any of bits 044, 004).
	const groupRead fs.FileMode = 0o040
	const otherRead fs.FileMode = 0o004

	if perm&(groupRead|otherRead) != 0 {
		slog.Warn(
			"config file has insecure permissions — tokens may be exposed to other users",
			"path", path,
			"mode", mode,
			"recommended", "0600",
		)
	}
}

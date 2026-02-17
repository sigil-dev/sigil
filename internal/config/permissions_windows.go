// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

//go:build windows

package config

import "log/slog"

// WarnInsecurePermissions is a no-op on Windows.
// Windows uses ACLs rather than Unix mode bits, so this check is not applicable.
func WarnInsecurePermissions(path string) {
	if path != "" {
		slog.Debug("config permission check not implemented on Windows", "path", path)
	}
}

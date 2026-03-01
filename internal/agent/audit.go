// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"log/slog"

	"github.com/sigil-dev/sigil/internal/security"
)

// logAuditFailure logs an audit append failure at an escalating level:
// Warn for the first (security.AuditLogEscalationThreshold - 1) consecutive
// failures, Error thereafter. This gives operators visibility into persistent
// audit failures without flooding the error log on transient blips.
//
// log must be non-nil; callers that do not have an injected logger should pass
// slog.Default().
func logAuditFailure(ctx context.Context, log *slog.Logger, consecutive int64, msg string, attrs ...slog.Attr) {
	logLevel := slog.LevelWarn
	if consecutive >= security.AuditLogEscalationThreshold {
		logLevel = slog.LevelError
	}
	log.LogAttrs(ctx, logLevel, msg, attrs...)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"log/slog"
)

// auditLogEscalationThreshold is the number of consecutive audit store append
// failures after which the log level escalates from Warn to Error. Used by both
// Loop.appendAuditEntry and ToolDispatcher.auditToolExecution so all audit
// failure paths share the same threshold.
const auditLogEscalationThreshold = 3

// logAuditFailure logs an audit append failure at an escalating level:
// Warn for the first (auditLogEscalationThreshold - 1) consecutive failures,
// Error thereafter. This gives operators visibility into persistent audit
// failures without flooding the error log on transient blips.
func logAuditFailure(ctx context.Context, consecutive int64, msg string, attrs ...slog.Attr) {
	logLevel := slog.LevelWarn
	if consecutive >= auditLogEscalationThreshold {
		logLevel = slog.LevelError
	}
	slog.LogAttrs(ctx, logLevel, msg, attrs...)
}

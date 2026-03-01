// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import "github.com/sigil-dev/sigil/internal/security"

// SanitizeToolError exposes sanitizeToolError for white-box testing.
// The method receiver is a zero-value Loop which is sufficient for the
// sanitisation logic (no fields accessed).
var SanitizeToolError = (&Loop{}).sanitizeToolError

// DefaultMaxToolContentScanSize exposes defaultMaxToolContentScanSize for white-box testing.
const DefaultMaxToolContentScanSize = defaultMaxToolContentScanSize

// DefaultMaxToolResultScanSize exposes defaultMaxToolResultScanSize for white-box testing.
const DefaultMaxToolResultScanSize = defaultMaxToolResultScanSize

// ScannerCircuitBreakerThreshold exposes scannerCircuitBreakerThreshold for white-box testing.
const ScannerCircuitBreakerThreshold = scannerCircuitBreakerThreshold

// TruncationMarker exposes truncationMarker for white-box testing.
const TruncationMarker = truncationMarker

// ScanBlockedReason exposes scanBlockedReason for white-box testing.
var ScanBlockedReason = scanBlockedReason

// ExportBuildBlockedAuditEntry exposes buildBlockedAuditEntry for white-box testing.
var ExportBuildBlockedAuditEntry = buildBlockedAuditEntry

// AuditLogEscalationThreshold re-exports security.AuditLogEscalationThreshold for test compatibility.
const AuditLogEscalationThreshold = security.AuditLogEscalationThreshold

// TruncateField exposes truncateField for white-box testing.
var TruncateField = truncateField

// MaxFactFieldLen exposes maxFactFieldLen for white-box testing.
const MaxFactFieldLen = maxFactFieldLen

// MaxPendingOrphans exposes maxPendingOrphans for white-box testing.
const MaxPendingOrphans = maxPendingOrphans

// MaxPendingFacts exposes maxPendingFacts for white-box testing.
const MaxPendingFacts = maxPendingFacts

// MaxPendingSummaryOrphans exposes maxPendingSummaryOrphans for white-box testing.
const MaxPendingSummaryOrphans = maxPendingSummaryOrphans

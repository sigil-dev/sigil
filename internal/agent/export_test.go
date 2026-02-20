// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

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

// AuditLogEscalationThreshold exposes auditLogEscalationThreshold for white-box testing.
const AuditLogEscalationThreshold = auditLogEscalationThreshold


// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

// SanitizeToolError exposes sanitizeToolError for white-box testing.
// The method receiver is a zero-value Loop which is sufficient for the
// sanitisation logic (no fields accessed).
var SanitizeToolError = (&Loop{}).sanitizeToolError

// MaxToolContentScanSize exposes maxToolContentScanSize for white-box testing.
const MaxToolContentScanSize = maxToolContentScanSize

// ScannerCircuitBreakerThreshold exposes scannerCircuitBreakerThreshold for white-box testing.
const ScannerCircuitBreakerThreshold = scannerCircuitBreakerThreshold

// TruncationMarker exposes truncationMarker for white-box testing.
const TruncationMarker = truncationMarker

// ScanBlockedReason exposes scanBlockedReason for white-box testing.
var ScanBlockedReason = scanBlockedReason

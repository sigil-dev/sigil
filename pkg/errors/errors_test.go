// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package errors_test

import (
	stderrors "errors"
	"fmt"
	"net/http"
	"testing"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// New / Errorf
// ---------------------------------------------------------------------------

func TestNewIncludesCodeAndFields(t *testing.T) {
	err := sigilerr.New(
		sigilerr.CodeConfigValidateInvalidValue,
		"invalid model configuration",
		sigilerr.FieldWorkspaceID("ws-123"),
		sigilerr.Field("provider", "openai"),
	)

	require.Error(t, err)
	assert.Equal(t, sigilerr.CodeConfigValidateInvalidValue, sigilerr.CodeOf(err))
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeConfigValidateInvalidValue))

	fields := sigilerr.FieldsOf(err)
	assert.Equal(t, "ws-123", fields["workspace_id"])
	assert.Equal(t, "openai", fields["provider"])
}

func TestNewWithNoFields(t *testing.T) {
	err := sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "connection lost")
	require.Error(t, err)
	assert.Equal(t, sigilerr.CodeStoreDatabaseFailure, sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "connection lost")
}

func TestErrorfFormatsMessage(t *testing.T) {
	err := sigilerr.Errorf(sigilerr.CodePluginRuntimeStartFailure, "loading plugin %s: port %d", "echo", 9090)
	require.Error(t, err)
	assert.Equal(t, sigilerr.CodePluginRuntimeStartFailure, sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "loading plugin echo: port 9090")
}

func TestErrorfWrapsInnerError(t *testing.T) {
	inner := stderrors.New("disk full")
	err := sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "write failed: %w", inner)
	require.Error(t, err)
	assert.ErrorIs(t, err, inner)
	assert.Equal(t, sigilerr.CodeStoreDatabaseFailure, sigilerr.CodeOf(err))
}

// ---------------------------------------------------------------------------
// Wrap / Wrapf
// ---------------------------------------------------------------------------

func TestWrapPreservesWrappedErrorAndCode(t *testing.T) {
	root := stderrors.New("record missing")
	err := sigilerr.Wrap(
		root,
		sigilerr.CodeStoreSessionGetNotFound,
		"loading session",
		sigilerr.FieldSessionID("sess-42"),
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, root)
	assert.Equal(t, sigilerr.CodeStoreSessionGetNotFound, sigilerr.CodeOf(err))
	assert.True(t, sigilerr.IsNotFound(err))
	assert.Equal(t, "sess-42", sigilerr.FieldsOf(err)["session_id"])
}

func TestWrapNilReturnsNil(t *testing.T) {
	assert.NoError(t, sigilerr.Wrap(nil, sigilerr.CodeServerInternalFailure, "ignored"))
}

func TestWrapfNilReturnsNil(t *testing.T) {
	assert.NoError(t, sigilerr.Wrapf(nil, sigilerr.CodeServerInternalFailure, "ignored %s", "arg"))
}

func TestWrapfFormatsAndPreservesChain(t *testing.T) {
	root := stderrors.New("timeout")
	err := sigilerr.Wrapf(root, sigilerr.CodeProviderUpstreamFailure, "calling %s model %s", "anthropic", "claude")

	require.Error(t, err)
	assert.ErrorIs(t, err, root)
	assert.Equal(t, sigilerr.CodeProviderUpstreamFailure, sigilerr.CodeOf(err))
	assert.Contains(t, err.Error(), "calling anthropic model claude")
}

func TestWrapWithFields(t *testing.T) {
	root := stderrors.New("denied")
	err := sigilerr.Wrap(root, sigilerr.CodePluginCapabilityDenied, "capability check",
		sigilerr.FieldPlugin("tool.exec"),
		sigilerr.FieldWorkspaceID("ws-1"),
	)

	fields := sigilerr.FieldsOf(err)
	assert.Equal(t, "tool.exec", fields["plugin"])
	assert.Equal(t, "ws-1", fields["workspace_id"])
}

// ---------------------------------------------------------------------------
// With
// ---------------------------------------------------------------------------

func TestWithAddsContextWithoutChangingCode(t *testing.T) {
	base := sigilerr.New(sigilerr.CodePluginCapabilityDenied, "missing capability")
	withCtx := sigilerr.With(base, sigilerr.FieldPlugin("tool.fs"))

	require.Error(t, withCtx)
	assert.Equal(t, sigilerr.CodePluginCapabilityDenied, sigilerr.CodeOf(withCtx))
	assert.Equal(t, "tool.fs", sigilerr.FieldsOf(withCtx)["plugin"])
}

func TestWithNilReturnsNil(t *testing.T) {
	assert.NoError(t, sigilerr.With(nil, sigilerr.FieldPlugin("x")))
}

func TestWithOnPlainErrorDefaultsToInternalCode(t *testing.T) {
	plain := stderrors.New("something broke")
	enriched := sigilerr.With(plain, sigilerr.FieldUserID("u-1"))

	require.Error(t, enriched)
	assert.Equal(t, sigilerr.CodeServerInternalFailure, sigilerr.CodeOf(enriched))
	assert.Equal(t, "u-1", sigilerr.FieldsOf(enriched)["user_id"])
}

// ---------------------------------------------------------------------------
// HasCode
// ---------------------------------------------------------------------------

func TestHasCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code sigilerr.Code
		want bool
	}{
		{
			name: "matching code",
			err:  sigilerr.New(sigilerr.CodeStoreEntityNotFound, "gone"),
			code: sigilerr.CodeStoreEntityNotFound,
			want: true,
		},
		{
			name: "non-matching code",
			err:  sigilerr.New(sigilerr.CodeStoreEntityNotFound, "gone"),
			code: sigilerr.CodeStoreDatabaseFailure,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			code: sigilerr.CodeStoreEntityNotFound,
			want: false,
		},
		{
			name: "plain stdlib error has no code",
			err:  stderrors.New("plain"),
			code: sigilerr.CodeServerInternalFailure,
			want: false,
		},
		{
			name: "wrapped coded error returns innermost code",
			err: sigilerr.Wrap(
				sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "inner"),
				sigilerr.CodeServerInternalFailure, "outer",
			),
			code: sigilerr.CodeStoreDatabaseFailure,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sigilerr.HasCode(tt.err, tt.code))
		})
	}
}

// ---------------------------------------------------------------------------
// CodeOf
// ---------------------------------------------------------------------------

func TestCodeOfNil(t *testing.T) {
	assert.Equal(t, sigilerr.Code(""), sigilerr.CodeOf(nil))
}

func TestCodeOfPlainError(t *testing.T) {
	assert.Equal(t, sigilerr.Code(""), sigilerr.CodeOf(stderrors.New("plain")))
}

func TestCodeOfReturnsInnermostCodedError(t *testing.T) {
	inner := sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "db")
	outer := sigilerr.Wrap(inner, sigilerr.CodeServerInternalFailure, "handler")
	// oops.AsOops walks to the deepest oops error, so CodeOf returns the innermost code.
	assert.Equal(t, sigilerr.CodeStoreDatabaseFailure, sigilerr.CodeOf(outer))
}

// ---------------------------------------------------------------------------
// FieldsOf
// ---------------------------------------------------------------------------

func TestFieldsOfNil(t *testing.T) {
	assert.Nil(t, sigilerr.FieldsOf(nil))
}

func TestFieldsOfPlainError(t *testing.T) {
	assert.Nil(t, sigilerr.FieldsOf(stderrors.New("plain")))
}

// ---------------------------------------------------------------------------
// FieldValue / Field / typed field helpers
// ---------------------------------------------------------------------------

func TestFieldValueCreatesAttr(t *testing.T) {
	attr := sigilerr.FieldValue("key", 42)
	assert.Equal(t, "key", attr.Key)
	assert.Equal(t, 42, attr.Value)
}

func TestFieldAliasMatchesFieldValue(t *testing.T) {
	a := sigilerr.FieldValue("k", "v")
	b := sigilerr.Field("k", "v")
	assert.Equal(t, a, b)
}

func TestTypedFieldHelpers(t *testing.T) {
	tests := []struct {
		name string
		attr sigilerr.Attr
		key  string
		val  string
	}{
		{"workspace_id", sigilerr.FieldWorkspaceID("ws-1"), "workspace_id", "ws-1"},
		{"session_id", sigilerr.FieldSessionID("s-1"), "session_id", "s-1"},
		{"user_id", sigilerr.FieldUserID("u-1"), "user_id", "u-1"},
		{"plugin", sigilerr.FieldPlugin("tool.fs"), "plugin", "tool.fs"},
		{"provider", sigilerr.FieldProvider("anthropic"), "provider", "anthropic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.key, tt.attr.Key)
			assert.Equal(t, tt.val, tt.attr.Value)
		})
	}
}

func TestFieldsWithEmptyKeyAreIgnored(t *testing.T) {
	err := sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "oops",
		sigilerr.Field("", "should-be-dropped"),
		sigilerr.FieldPlugin("kept"),
	)
	fields := sigilerr.FieldsOf(err)
	assert.Equal(t, "kept", fields["plugin"])
	assert.NotContains(t, fields, "")
}

// ---------------------------------------------------------------------------
// errors.Is / errors.As unwrapping
// ---------------------------------------------------------------------------

func TestErrorIsWithWrappedChain(t *testing.T) {
	sentinel := stderrors.New("root cause")
	mid := fmt.Errorf("mid: %w", sentinel)
	outer := sigilerr.Wrap(mid, sigilerr.CodeServerInternalFailure, "handler")

	assert.ErrorIs(t, outer, sentinel)
}

func TestErrorIsWithMultiWrap(t *testing.T) {
	sentinel := stderrors.New("original")
	first := sigilerr.Wrap(sentinel, sigilerr.CodeStoreDatabaseFailure, "layer 1")
	second := sigilerr.Wrap(first, sigilerr.CodeServerInternalFailure, "layer 2")

	assert.ErrorIs(t, second, sentinel)
	// CodeOf returns the innermost coded error (first wrap layer).
	assert.Equal(t, sigilerr.CodeStoreDatabaseFailure, sigilerr.CodeOf(second))
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

func TestClassificationAndStatusMapping(t *testing.T) {
	tests := []struct {
		name   string
		code   sigilerr.Code
		status int
		check  func(error) bool
	}{
		{name: "not found", code: sigilerr.CodeStoreSessionGetNotFound, status: 404, check: sigilerr.IsNotFound},
		{name: "entity not found", code: sigilerr.CodeStoreEntityNotFound, status: 404, check: sigilerr.IsNotFound},
		{name: "server entity not found", code: sigilerr.CodeServerEntityNotFound, status: 404, check: sigilerr.IsNotFound},
		{name: "provider not found", code: sigilerr.CodeProviderNotFound, status: 404, check: sigilerr.IsNotFound},
		{name: "conflict", code: sigilerr.CodeStoreSessionUpdateConflict, status: 409, check: sigilerr.IsConflict},
		{name: "store conflict", code: sigilerr.CodeStoreConflict, status: 409, check: sigilerr.IsConflict},
		{name: "invalid value", code: sigilerr.CodeConfigValidateInvalidValue, status: 400, check: sigilerr.IsInvalidInput},
		{name: "invalid format", code: sigilerr.CodeConfigParseInvalidFormat, status: 400, check: sigilerr.IsInvalidInput},
		{name: "invalid input", code: sigilerr.CodeStoreInvalidInput, status: 400, check: sigilerr.IsInvalidInput},
		{name: "manifest invalid", code: sigilerr.CodePluginManifestValidateInvalid, status: 400, check: sigilerr.IsInvalidInput},
		{name: "unauthorized", code: sigilerr.CodeServerAuthUnauthorized, status: 401, check: sigilerr.IsUnauthorized},
		{name: "forbidden", code: sigilerr.CodeServerAuthForbidden, status: 403, check: sigilerr.IsUnauthorized},
		{name: "capability denied", code: sigilerr.CodePluginCapabilityDenied, status: 403, check: sigilerr.IsUnauthorized},
		{name: "budget exceeded (provider)", code: sigilerr.CodeProviderBudgetExceeded, status: 429, check: sigilerr.IsBudgetExceeded},
		{name: "budget exceeded (tool)", code: sigilerr.CodeAgentToolBudgetExceeded, status: 429, check: sigilerr.IsBudgetExceeded},
		{name: "tool timeout", code: sigilerr.CodeAgentToolTimeout, status: 504, check: sigilerr.IsTimeout},
		{name: "upstream failure", code: sigilerr.CodeProviderUpstreamFailure, status: 502, check: sigilerr.IsUpstreamFailure},
		{name: "not implemented", code: sigilerr.CodeServerNotImplemented, status: 501, check: func(_ error) bool { return true }},
		{name: "internal", code: sigilerr.CodeServerInternalFailure, status: 500, check: func(err error) bool { return !sigilerr.IsNotFound(err) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sigilerr.New(tt.code, "boom")
			assert.Equal(t, tt.status, sigilerr.HTTPStatus(err))
			assert.True(t, tt.check(err))
		})
	}
}

func TestClassificationNegativeCases(t *testing.T) {
	err := sigilerr.New(sigilerr.CodeStoreDatabaseFailure, "db error")
	assert.False(t, sigilerr.IsNotFound(err))
	assert.False(t, sigilerr.IsConflict(err))
	assert.False(t, sigilerr.IsInvalidInput(err))
	assert.False(t, sigilerr.IsUnauthorized(err))
	assert.False(t, sigilerr.IsBudgetExceeded(err))
	assert.False(t, sigilerr.IsTimeout(err))
	assert.False(t, sigilerr.IsUpstreamFailure(err))
}

func TestClassificationOnNilError(t *testing.T) {
	assert.False(t, sigilerr.IsNotFound(nil))
	assert.False(t, sigilerr.IsConflict(nil))
	assert.False(t, sigilerr.IsInvalidInput(nil))
	assert.False(t, sigilerr.IsUnauthorized(nil))
	assert.False(t, sigilerr.IsBudgetExceeded(nil))
	assert.False(t, sigilerr.IsTimeout(nil))
	assert.False(t, sigilerr.IsUpstreamFailure(nil))
}

func TestClassificationOnPlainError(t *testing.T) {
	err := stderrors.New("plain")
	assert.False(t, sigilerr.IsNotFound(err))
	assert.False(t, sigilerr.IsConflict(err))
	assert.False(t, sigilerr.IsInvalidInput(err))
	assert.False(t, sigilerr.IsUnauthorized(err))
	assert.False(t, sigilerr.IsBudgetExceeded(err))
	assert.False(t, sigilerr.IsTimeout(err))
	assert.False(t, sigilerr.IsUpstreamFailure(err))
}

// ---------------------------------------------------------------------------
// HTTPStatus edge cases
// ---------------------------------------------------------------------------

func TestHTTPStatusNilReturnsInternalServerError(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError, sigilerr.HTTPStatus(nil))
}

func TestHTTPStatusPlainErrorReturnsInternalServerError(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError, sigilerr.HTTPStatus(stderrors.New("oops")))
}

// ---------------------------------------------------------------------------
// Join
// ---------------------------------------------------------------------------

func TestJoinCombinesErrors(t *testing.T) {
	a := stderrors.New("first")
	b := stderrors.New("second")
	joined := sigilerr.Join(a, b)

	require.Error(t, joined)
	assert.ErrorIs(t, joined, a)
	assert.ErrorIs(t, joined, b)
	assert.Equal(t, sigilerr.CodeServerInternalFailure, sigilerr.CodeOf(joined))
}

// ---------------------------------------------------------------------------
// Nested wrapping preserves outermost code
// ---------------------------------------------------------------------------

func TestNestedWrapInnermostCodePersists(t *testing.T) {
	root := stderrors.New("io error")
	l1 := sigilerr.Wrap(root, sigilerr.CodeStoreDatabaseFailure, "store layer")
	l2 := sigilerr.Wrap(l1, sigilerr.CodePluginRuntimeCallFailure, "plugin layer")
	l3 := sigilerr.Wrap(l2, sigilerr.CodeServerInternalFailure, "server layer")

	// oops walks to the deepest coded error, so CodeOf returns the first code set.
	assert.Equal(t, sigilerr.CodeStoreDatabaseFailure, sigilerr.CodeOf(l3))
	assert.ErrorIs(t, l3, root)
}

// ---------------------------------------------------------------------------
// Error message content
// ---------------------------------------------------------------------------

func TestWrapMessageIncludesContext(t *testing.T) {
	root := stderrors.New("EOF")
	err := sigilerr.Wrap(root, sigilerr.CodeStoreDatabaseFailure, "reading rows")

	msg := err.Error()
	assert.Contains(t, msg, "reading rows")
	assert.Contains(t, msg, "EOF")
}

func TestNewMessageContent(t *testing.T) {
	err := sigilerr.New(sigilerr.CodeAgentLoopFailure, "max iterations reached")
	assert.Contains(t, err.Error(), "max iterations reached")
}

// ---------------------------------------------------------------------------
// IsScannerCode
// ---------------------------------------------------------------------------

func TestIsScannerCode(t *testing.T) {
	scannerCodes := []sigilerr.Code{
		sigilerr.CodeSecurityScannerInputBlocked,
		sigilerr.CodeSecurityScannerOutputBlocked,
		sigilerr.CodeSecurityScannerToolBlocked,
		sigilerr.CodeSecurityScannerContentTooLarge,
		sigilerr.CodeSecurityScannerFailure,
		sigilerr.CodeSecurityScannerCancelled,
		sigilerr.CodeSecurityScannerCircuitBreakerOpen,
		sigilerr.CodeSecurityScannerEmptyRuleStage,
	}

	for _, code := range scannerCodes {
		t.Run(string(code), func(t *testing.T) {
			err := sigilerr.New(code, "scanner error")
			assert.True(t, sigilerr.IsScannerCode(err))
		})
	}

	nonScannerCodes := []sigilerr.Code{
		sigilerr.CodeServerInternalFailure,
		sigilerr.CodeProviderUpstreamFailure,
		sigilerr.CodeSecurityCapabilityInvalid,
		sigilerr.CodeSecurityInvalidInput,
	}

	for _, code := range nonScannerCodes {
		t.Run("non-scanner/"+string(code), func(t *testing.T) {
			err := sigilerr.New(code, "non-scanner error")
			assert.False(t, sigilerr.IsScannerCode(err))
		})
	}
}

func TestIsScannerCodeNil(t *testing.T) {
	assert.False(t, sigilerr.IsScannerCode(nil))
}

// ---------------------------------------------------------------------------
// HTTPStatus — scanner error codes
// ---------------------------------------------------------------------------

func TestHTTPStatusScannerCodes(t *testing.T) {
	tests := []struct {
		name string
		code sigilerr.Code
		want int
	}{
		// Input blocked: client sent content that was rejected → 422 Unprocessable Entity.
		{
			name: "input blocked → 422",
			code: sigilerr.CodeSecurityScannerInputBlocked,
			want: http.StatusUnprocessableEntity,
		},
		// All other scanner codes reflect a service-side or transient condition → 503.
		{
			name: "output blocked → 503",
			code: sigilerr.CodeSecurityScannerOutputBlocked,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "tool blocked → 503",
			code: sigilerr.CodeSecurityScannerToolBlocked,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "circuit breaker open → 503",
			code: sigilerr.CodeSecurityScannerCircuitBreakerOpen,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "content too large → 503",
			code: sigilerr.CodeSecurityScannerContentTooLarge,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "cancelled → 503",
			code: sigilerr.CodeSecurityScannerCancelled,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "scanner failure → 503",
			code: sigilerr.CodeSecurityScannerFailure,
			want: http.StatusServiceUnavailable,
		},
		{
			name: "empty rule stage → 503",
			code: sigilerr.CodeSecurityScannerEmptyRuleStage,
			want: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sigilerr.New(tt.code, "scanner error")
			assert.Equal(t, tt.want, sigilerr.HTTPStatus(err))
		})
	}
}

// ---------------------------------------------------------------------------
// HTTPStatusFromCode
// ---------------------------------------------------------------------------

func TestHTTPStatusFromCode(t *testing.T) {
	tests := []struct {
		name string
		code sigilerr.Code
		want int
	}{
		// Security scanner: input_blocked → 422 (client content rejection).
		{name: "input_blocked → 422", code: sigilerr.CodeSecurityScannerInputBlocked, want: http.StatusUnprocessableEntity},
		// Security scanner: all other → 503 (service-side transient).
		{name: "tool_blocked → 503", code: sigilerr.CodeSecurityScannerToolBlocked, want: http.StatusServiceUnavailable},
		{name: "output_blocked → 503", code: sigilerr.CodeSecurityScannerOutputBlocked, want: http.StatusServiceUnavailable},
		{name: "content_too_large → 503", code: sigilerr.CodeSecurityScannerContentTooLarge, want: http.StatusServiceUnavailable},
		{name: "scanner_failure → 503", code: sigilerr.CodeSecurityScannerFailure, want: http.StatusServiceUnavailable},
		{name: "scanner_cancelled → 503", code: sigilerr.CodeSecurityScannerCancelled, want: http.StatusServiceUnavailable},
		{name: "circuit_breaker_open → 503", code: sigilerr.CodeSecurityScannerCircuitBreakerOpen, want: http.StatusServiceUnavailable},
		{name: "empty_rule_stage → 503", code: sigilerr.CodeSecurityScannerEmptyRuleStage, want: http.StatusServiceUnavailable},
		// Invalid input codes → 400.
		{name: "security.capability.invalid → 400", code: sigilerr.CodeSecurityCapabilityInvalid, want: http.StatusBadRequest},
		{name: "security.input.invalid → 400", code: sigilerr.CodeSecurityInvalidInput, want: http.StatusBadRequest},
		{name: "agent.loop.invalid_input → 400", code: sigilerr.CodeAgentLoopInvalidInput, want: http.StatusBadRequest},
		{name: "agent.skill.parse.invalid → 400", code: sigilerr.CodeAgentSkillParseInvalid, want: http.StatusBadRequest},
		{name: "config.validate.invalid_value → 400", code: sigilerr.CodeConfigValidateInvalidValue, want: http.StatusBadRequest},
		{name: "plugin.manifest.validate.invalid → 400", code: sigilerr.CodePluginManifestValidateInvalid, want: http.StatusBadRequest},
		// Upstream/provider failures → 502.
		{name: "provider.upstream.failure → 502", code: sigilerr.CodeProviderUpstreamFailure, want: http.StatusBadGateway},
		// Budget exceeded → 429.
		{name: "agent.tool.budget_exceeded → 429", code: sigilerr.CodeAgentToolBudgetExceeded, want: http.StatusTooManyRequests},
		{name: "provider.budget.exceeded → 429", code: sigilerr.CodeProviderBudgetExceeded, want: http.StatusTooManyRequests},
		// Timeout → 504.
		{name: "agent.tool.timeout → 504", code: sigilerr.CodeAgentToolTimeout, want: http.StatusGatewayTimeout},
		// Unknown/empty → 502 (default fallback).
		{name: "empty code → 502", code: sigilerr.Code(""), want: http.StatusBadGateway},
		{name: "unknown code → 502", code: sigilerr.Code("some.unknown.code"), want: http.StatusBadGateway},
		{name: "store.database.failure → 502", code: sigilerr.CodeStoreDatabaseFailure, want: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sigilerr.HTTPStatusFromCode(tt.code))
		})
	}
}

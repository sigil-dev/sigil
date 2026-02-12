// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package errors_test

import (
	stderrors "errors"
	"testing"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestWithAddsContextWithoutChangingCode(t *testing.T) {
	base := sigilerr.New(sigilerr.CodePluginCapabilityDenied, "missing capability")
	withCtx := sigilerr.With(base, sigilerr.FieldPlugin("tool.fs"))

	require.Error(t, withCtx)
	assert.Equal(t, sigilerr.CodePluginCapabilityDenied, sigilerr.CodeOf(withCtx))
	assert.Equal(t, "tool.fs", sigilerr.FieldsOf(withCtx)["plugin"])
}

func TestClassificationAndStatusMapping(t *testing.T) {
	tests := []struct {
		name   string
		code   sigilerr.Code
		status int
		check  func(error) bool
	}{
		{name: "not found", code: sigilerr.CodeStoreSessionGetNotFound, status: 404, check: sigilerr.IsNotFound},
		{name: "conflict", code: sigilerr.CodeStoreSessionUpdateConflict, status: 409, check: sigilerr.IsConflict},
		{name: "invalid", code: sigilerr.CodeConfigValidateInvalidValue, status: 400, check: sigilerr.IsInvalidInput},
		{name: "unauthorized", code: sigilerr.CodeServerAuthUnauthorized, status: 401, check: sigilerr.IsUnauthorized},
		{name: "budget exceeded (provider)", code: sigilerr.CodeProviderBudgetExceeded, status: 429, check: sigilerr.IsBudgetExceeded},
		{name: "budget exceeded (tool)", code: sigilerr.CodeAgentToolBudgetExceeded, status: 429, check: sigilerr.IsBudgetExceeded},
		{name: "tool timeout", code: sigilerr.CodeAgentToolTimeout, status: 504, check: sigilerr.IsTimeout},
		{name: "upstream failure", code: sigilerr.CodeProviderUpstreamFailure, status: 502, check: sigilerr.IsUpstreamFailure},
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

func TestWrapNilReturnsNil(t *testing.T) {
	assert.NoError(t, sigilerr.Wrap(nil, sigilerr.CodeServerInternalFailure, "ignored"))
}

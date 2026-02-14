// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/samber/oops"
)

// Code is the machine-readable identifier for an error.
type Code string

const (
	CodeStoreSessionGetNotFound     Code = "store.session.get.not_found"
	CodeStoreSessionUpdateConflict  Code = "store.session.update.conflict"
	CodeStoreEntityNotFound         Code = "store.entity.get.not_found"
	CodeStoreMessageAppendInvalid   Code = "store.message.append.invalid_input"
	CodeStoreKnowledgeQueryDatabase Code = "store.knowledge.query.database_failure"
	CodeStoreDatabaseFailure        Code = "store.database.failure"
	CodeStoreBackendUnsupported     Code = "store.backend.unsupported"
	CodeStoreConflict               Code = "store.conflict"
	CodeStoreInvalidInput           Code = "store.invalid_input"

	CodeConfigLoadReadFailure      Code = "config.load.read.failure"
	CodeConfigParseInvalidFormat   Code = "config.parse.invalid_format"
	CodeConfigValidateInvalidValue Code = "config.validate.invalid_value"

	CodePluginManifestValidateInvalid    Code = "plugin.manifest.validate.invalid"
	CodePluginCapabilityDenied           Code = "plugin.capability.denied"
	CodePluginRuntimeStartFailure        Code = "plugin.runtime.start.failure"
	CodePluginRuntimeCallFailure         Code = "plugin.runtime.call.failure"
	CodePluginLifecycleTransitionInvalid Code = "plugin.lifecycle.transition.invalid"
	CodePluginDiscoveryFailure           Code = "plugin.discovery.failure"
	CodePluginNotFound                   Code = "plugin.not_found"
	CodePluginChannelNotFound            Code = "plugin.channel.not_found"
	CodePluginSandboxPathInvalid         Code = "plugin.sandbox.path.invalid"
	CodePluginSandboxUnsupported         Code = "plugin.sandbox.unsupported"
	CodePluginSandboxSetupFailure        Code = "plugin.sandbox.setup.failure"
	CodePluginSandboxNetworkInvalid      Code = "plugin.sandbox.network.invalid"

	CodeProviderRequestInvalid  Code = "provider.request.invalid"
	CodeProviderResponseInvalid Code = "provider.response.invalid"
	CodeProviderUpstreamFailure Code = "provider.upstream.failure"
	CodeProviderBudgetExceeded  Code = "provider.budget.exceeded"
	CodeProviderNotFound        Code = "provider.registry.not_found"
	CodeProviderAllUnavailable  Code = "provider.routing.all_unavailable"
	CodeProviderNoDefault        Code = "provider.routing.no_default"
	CodeProviderInvalidModelRef  Code = "provider.routing.invalid_model_ref"

	CodeAgentLoopInvalidInput        Code = "agent.loop.invalid_input"
	CodeAgentLoopFailure             Code = "agent.loop.failure"
	CodeAgentSessionBoundaryMismatch Code = "agent.session.boundary.forbidden"
	CodeAgentSessionInactive         Code = "agent.session.status.forbidden"
	CodeAgentToolBudgetExceeded      Code = "agent.tool.budget_exceeded"
	CodeAgentToolTimeout             Code = "agent.tool.timeout"
	CodeAgentSkillParseInvalid       Code = "agent.skill.parse.invalid"

	CodeWorkspaceOpenFailure      Code = "workspace.open.failure"
	CodeWorkspaceMembershipDenied Code = "workspace.membership.denied"
	CodeWorkspaceConfigInvalid    Code = "workspace.config.invalid"
	CodeWorkspaceCloseFailure    Code = "workspace.close.failure"

	CodeServerRequestInvalid   Code = "server.request.invalid"
	CodeServerAuthUnauthorized Code = "server.auth.unauthorized"
	CodeServerAuthForbidden    Code = "server.auth.forbidden"
	CodeServerInternalFailure  Code = "server.internal.failure"
	CodeServerEntityNotFound   Code = "server.entity.not_found"
	CodeServerConfigInvalid    Code = "server.config.invalid"
	CodeServerStartFailure     Code = "server.start.failure"
	CodeServerShutdownFailure  Code = "server.shutdown.failure"
	CodeServerNotImplemented   Code = "server.method.not_implemented"

	CodeCLIGatewayNotRunning Code = "cli.gateway.not_running"
	CodeCLIRequestFailure    Code = "cli.request.failure"
	CodeCLIResponseInvalid   Code = "cli.response.invalid"
	CodeCLISetupFailure      Code = "cli.setup.failure"
	CodeCLIInputInvalid      Code = "cli.input.invalid"

	CodeSecurityCapabilityInvalid Code = "security.capability.invalid"

	CodeChannelPairingRequired Code = "channel.pairing.required"
	CodeChannelPairingDenied   Code = "channel.pairing.denied"
	CodeChannelPairingPending  Code = "channel.pairing.pending"
	CodeChannelBackendFailure  Code = "channel.backend.failure"
)

// Field is a structured key/value context attached to an error.
type Attr struct {
	Key   string
	Value any
}

// Field creates a structured error field.
func FieldValue(key string, value any) Attr {
	return Attr{Key: key, Value: value}
}

// Field is kept as the primary helper for terse callsites.
func Field(key string, value any) Attr {
	return FieldValue(key, value)
}

func FieldWorkspaceID(value string) Attr {
	return Field("workspace_id", value)
}

func FieldSessionID(value string) Attr {
	return Field("session_id", value)
}

func FieldUserID(value string) Attr {
	return Field("user_id", value)
}

func FieldPlugin(value string) Attr {
	return Field("plugin", value)
}

func FieldProvider(value string) Attr {
	return Field("provider", value)
}

func New(code Code, msg string, fields ...Attr) error {
	return oops.Code(code).With(flatten(fields)...).New(msg)
}

func Errorf(code Code, format string, args ...any) error {
	return oops.Code(code).Errorf(format, args...)
}

func Wrap(err error, code Code, msg string, fields ...Attr) error {
	if err == nil {
		return nil
	}

	return oops.Code(code).With(flatten(fields)...).Wrapf(err, "%s", msg)
}

func Wrapf(err error, code Code, format string, args ...any) error {
	if err == nil {
		return nil
	}

	return oops.Code(code).Wrapf(err, format, args...)
}

// With adds structured fields to an existing error chain.
func With(err error, fields ...Attr) error {
	if err == nil {
		return nil
	}

	code := CodeOf(err)
	if code == "" {
		code = CodeServerInternalFailure
	}

	return oops.Code(code).With(flatten(fields)...).Wrap(err)
}

func CodeOf(err error) Code {
	if err == nil {
		return ""
	}

	oopsErr, ok := oops.AsOops(err)
	if !ok {
		return ""
	}

	if code, ok := oopsErr.Code().(Code); ok {
		return code
	}

	if code, ok := oopsErr.Code().(string); ok {
		return Code(code)
	}

	return Code(fmt.Sprintf("%v", oopsErr.Code()))
}

func FieldsOf(err error) map[string]any {
	if err == nil {
		return nil
	}

	oopsErr, ok := oops.AsOops(err)
	if !ok {
		return nil
	}

	return oopsErr.Context()
}

func HasCode(err error, code Code) bool {
	if err == nil {
		return false
	}
	return CodeOf(err) == code
}

func IsNotFound(err error) bool {
	return reason(CodeOf(err)) == "not_found"
}

func IsConflict(err error) bool {
	return reason(CodeOf(err)) == "conflict"
}

func IsInvalidInput(err error) bool {
	r := reason(CodeOf(err))
	return r == "invalid" || r == "invalid_input" || r == "invalid_value" || r == "invalid_format"
}

func IsUnauthorized(err error) bool {
	r := reason(CodeOf(err))
	return r == "unauthorized" || r == "forbidden" || r == "denied"
}

func IsBudgetExceeded(err error) bool {
	r := reason(CodeOf(err))
	return r == "exceeded" || r == "budget_exceeded"
}

func IsTimeout(err error) bool {
	return reason(CodeOf(err)) == "timeout"
}

func IsUpstreamFailure(err error) bool {
	code := CodeOf(err)
	return strings.Contains(string(code), "upstream") && reason(code) == "failure"
}

func HTTPStatus(err error) int {
	switch {
	case HasCode(err, CodeServerNotImplemented):
		return http.StatusNotImplemented
	case IsNotFound(err):
		return http.StatusNotFound
	case IsConflict(err):
		return http.StatusConflict
	case IsInvalidInput(err):
		return http.StatusBadRequest
	case IsUnauthorized(err):
		if reason(CodeOf(err)) == "forbidden" || reason(CodeOf(err)) == "denied" {
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	case IsBudgetExceeded(err):
		return http.StatusTooManyRequests
	case IsTimeout(err):
		return http.StatusGatewayTimeout
	case IsUpstreamFailure(err):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func Join(errs ...error) error {
	return oops.Code(CodeServerInternalFailure).Wrap(stderrors.Join(errs...))
}

func flatten(fields []Attr) []any {
	pairs := make([]any, 0, len(fields)*2)
	for _, field := range fields {
		if field.Key == "" {
			continue
		}
		pairs = append(pairs, field.Key, field.Value)
	}
	return pairs
}

func reason(code Code) string {
	if code == "" {
		return ""
	}

	raw := string(code)
	idx := strings.LastIndex(raw, ".")
	if idx == -1 || idx == len(raw)-1 {
		return raw
	}
	return raw[idx+1:]
}

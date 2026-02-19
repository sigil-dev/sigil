// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// primeViperDefaults populates the global Viper instance with the same
// defaults that initViper applies, so runStart can call config.FromViper
// without discovering a config file. Tests that call runStart directly
// (bypassing the cobra PersistentPreRunE) must call this first.
func primeViperDefaults(v *viper.Viper) {
	v.SetDefault("networking.mode", "local")
	v.SetDefault("networking.listen", "127.0.0.1:18789")
	v.SetDefault("storage.backend", "sqlite")
	v.SetDefault("sessions.memory.active_window", 20)
	v.SetDefault("sessions.memory.compaction.strategy", "summarize")
	v.SetDefault("sessions.memory.compaction.summary_model", "anthropic/claude-haiku-4-5")
	v.SetDefault("sessions.memory.compaction.batch_size", 50)
	v.SetDefault("models.default", "anthropic/claude-sonnet-4-5")
	v.SetDefault("models.budgets.per_session_tokens", 100000)
	v.SetDefault("models.budgets.per_hour_usd", 5.00)
	v.SetDefault("models.budgets.per_day_usd", 50.00)
	v.SetDefault("security.scanner.input", "block")
	v.SetDefault("security.scanner.tool", "flag")
	v.SetDefault("security.scanner.output", "redact")
	v.SetDefault("security.scanner.allow_permissive_input_mode", false)
	v.SetDefault("security.scanner.disable_origin_tagging", false)
	v.SetDefault("security.scanner.limits.max_content_length", 1048576)
	v.SetDefault("security.scanner.limits.max_pre_norm_content_length", 5242880)
	v.SetDefault("security.scanner.limits.max_tool_result_scan_size", 1048576)
	v.SetDefault("security.scanner.limits.max_tool_content_scan_size", 524288)
}

// TestRunStart_SecurityValidationFailure verifies that runStart returns a
// CodeCLISetupFailure error when ValidateSecurity() detects a security policy
// violation, and that the error is returned before WireGateway is reached.
//
// ValidateSecurity() rejects scanner mode settings delivered via environment
// variables to prevent container orchestrators or CI systems from silently
// weakening the security pipeline. The error message prefix "loading config:"
// (from the config.FromViper call, which itself runs Validate → ValidateSecurity)
// proves the rejection fires before the "wiring gateway:" path, i.e., before
// any subsystem is initialized.
//
// The test covers three distinct env-var injection vectors to exercise the full
// breadth of the env-var guard in ValidateSecurity().
func TestRunStart_SecurityValidationFailure(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func(t *testing.T)
		wantMsgFrag string // substring that must appear in the error message
	}{
		{
			// SIGIL_SECURITY_SCANNER_INPUT set to any non-empty value is blocked
			// by the env-var injection guard in ValidateSecurity().
			name: "SIGIL_SECURITY_SCANNER_INPUT env var rejected",
			setupEnv: func(t *testing.T) {
				t.Setenv("SIGIL_SECURITY_SCANNER_INPUT", "flag")
			},
			wantMsgFrag: "SIGIL_SECURITY_SCANNER_INPUT",
		},
		{
			// SIGIL_SECURITY_SCANNER_OUTPUT is similarly blocked; any non-empty
			// value triggers the guard.
			name: "SIGIL_SECURITY_SCANNER_OUTPUT env var rejected",
			setupEnv: func(t *testing.T) {
				t.Setenv("SIGIL_SECURITY_SCANNER_OUTPUT", "off")
			},
			wantMsgFrag: "SIGIL_SECURITY_SCANNER_OUTPUT",
		},
		{
			// SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE=true is also
			// guarded; the boolBlockOnTrue flag means only the literal "true"
			// value (case-insensitive) triggers the error.
			name: "SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE=true env var rejected",
			setupEnv: func(t *testing.T) {
				t.Setenv("SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE", "true")
			},
			wantMsgFrag: "SIGIL_SECURITY_SCANNER_ALLOW_PERMISSIVE_INPUT_MODE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the global Viper instance so state from one sub-test
			// cannot bleed into the next.
			viper.Reset()

			// Apply the environment variable that triggers security validation
			// failure. t.Setenv automatically restores the original value on
			// cleanup so parallel sub-tests are isolated.
			tt.setupEnv(t)

			// Build a minimal cobra.Command that satisfies runStart's flag
			// lookup for "listen". We bypass the PersistentPreRunE (initViper)
			// and prime Viper directly so no config file is required.
			cmd := &cobra.Command{}
			cmd.Flags().String("listen", "", "override listen address")
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Prime global Viper with defaults, env prefix, and key replacer
			// so that env vars are mapped to config keys using the same
			// convention as initViper (SetupEnv). AutomaticEnv ensures the
			// t.Setenv changes above are picked up during unmarshalling.
			v := viper.GetViper()
			primeViperDefaults(v)
			v.SetEnvPrefix("SIGIL")
			v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
			v.AutomaticEnv()

			err := runStart(cmd, nil)

			// runStart must return an error — security validation must have fired.
			require.Error(t, err, "runStart must return an error when a security env var is set")

			// runStart wraps all early-exit errors with CodeCLISetupFailure.
			assert.True(t, sigilerr.HasCode(err, sigilerr.CodeCLISetupFailure),
				"error must carry CodeCLISetupFailure; got: %v", err)

			// The error message must identify the rejected env var so that
			// operators can diagnose and fix the violation.
			assert.Contains(t, err.Error(), tt.wantMsgFrag,
				"error message must name the rejected env var")

			// The error must NOT contain "wiring gateway" — that substring
			// only appears if WireGateway was reached. Its absence proves the
			// security gate fired before any subsystem was initialized.
			assert.NotContains(t, err.Error(), "wiring gateway",
				"security rejection must fire before WireGateway is called")
		})
	}
}

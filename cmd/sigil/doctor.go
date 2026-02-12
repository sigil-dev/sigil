// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostics",
		Long:  "Check binary health, provider API keys, channel connections, disk space, and other system requirements.",
		RunE:  runDoctor,
	}
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()

	checks := []struct {
		name string
		fn   func() string
	}{
		{"Binary", checkBinary},
		{"Platform", checkPlatform},
	}

	for _, c := range checks {
		if _, err := fmt.Fprintf(w, "%-20s %s\n", c.name+":", c.fn()); err != nil {
			return err
		}
	}

	// TODO: Add checks for providers, channels, disk space, Tailscale once subsystems are wired.
	_, err := fmt.Fprintln(w, "\nAdditional checks will be available once the gateway is running.")
	return err
}

func checkBinary() string {
	return fmt.Sprintf("sigil %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func checkPlatform() string {
	return fmt.Sprintf("%s/%s, Go %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

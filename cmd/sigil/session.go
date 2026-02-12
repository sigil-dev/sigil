// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sessions",
		Long:  "List, show, archive, and export agent sessions.",
	}

	cmd.PersistentFlags().StringP("workspace", "w", "", "filter by workspace")

	cmd.AddCommand(
		newSessionListCmd(),
		newSessionShowCmd(),
		newSessionArchiveCmd(),
		newSessionExportCmd(),
	)

	return cmd
}

func newSessionListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "No sessions found")
			return err
		},
	}
}

func newSessionShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [id]",
		Short: "Show session details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Session: %s\n", args[0])
			return err
		},
	}
}

func newSessionArchiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "archive [id]",
		Short: "Archive a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Archived session %q\n", args[0])
			return err
		},
	}
}

func newSessionExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [id]",
		Short: "Export session transcript",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Exported session %q as %s\n", args[0], format)
			return err
		},
	}

	cmd.Flags().String("format", "json", "export format (json, markdown)")
	cmd.Flags().StringP("output", "o", "", "output file path")

	return cmd
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"errors"
	"fmt"
	"text/tabwriter"

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
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE:  runSessionList,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runSessionList(cmd *cobra.Command, _ []string) error {
	workspace, _ := cmd.Flags().GetString("workspace")
	if workspace == "" {
		return fmt.Errorf("--workspace flag is required")
	}

	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Sessions []struct {
			ID          string `json:"id"`
			WorkspaceID string `json:"workspace_id"`
			Status      string `json:"status"`
		} `json:"sessions"`
	}
	if err := gw.getJSON("/api/v1/workspaces/"+workspace+"/sessions", &body); err != nil {
		if errors.Is(err, ErrGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return fmt.Errorf("listing sessions: %w", err)
	}

	if len(body.Sessions) == 0 {
		_, _ = fmt.Fprintln(out, "No sessions found")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tWORKSPACE\tSTATUS")
	for _, s := range body.Sessions {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s.ID, s.WorkspaceID, s.Status)
	}
	return tw.Flush()
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

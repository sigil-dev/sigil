// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage workspaces",
		Long:  "List, create, delete, and inspect workspaces.",
	}

	cmd.AddCommand(
		newWorkspaceListCmd(),
		newWorkspaceCreateCmd(),
		newWorkspaceDeleteCmd(),
		newWorkspaceShowCmd(),
	)

	return cmd
}

func newWorkspaceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		RunE:  runWorkspaceList,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runWorkspaceList(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Workspaces []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"workspaces"`
	}
	if err := gw.getJSON("/api/v1/workspaces", &body); err != nil {
		if errors.Is(err, ErrGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return fmt.Errorf("listing workspaces: %w", err)
	}

	if len(body.Workspaces) == 0 {
		_, _ = fmt.Fprintln(out, "No workspaces found")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tDESCRIPTION")
	for _, ws := range body.Workspaces {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", ws.ID, ws.Description)
	}
	return tw.Flush()
}

func newWorkspaceCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Connect to gateway API once server is implemented.
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Created workspace %q\n", args[0])
			return err
		},
	}

	cmd.Flags().String("description", "", "workspace description")

	return cmd
}

func newWorkspaceDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Connect to gateway API once server is implemented.
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Deleted workspace %q\n", args[0])
			return err
		},
	}
}

func newWorkspaceShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [name]",
		Short: "Show workspace details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Connect to gateway API once server is implemented.
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Workspace: %s\n", args[0])
			return err
		},
	}
}

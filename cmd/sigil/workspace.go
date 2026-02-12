// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

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
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// TODO: Connect to gateway API once server is implemented.
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "No workspaces configured")
			return err
		},
	}
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

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [message]",
		Short: "Chat with an agent",
		Long:  "Send a message to an agent via the gateway. Starts an interactive session if no message is provided.",
		RunE:  runChat,
	}

	cmd.Flags().StringP("workspace", "w", "", "workspace to chat in")
	cmd.Flags().StringP("model", "m", "", "model override")
	cmd.Flags().StringP("session", "s", "", "resume existing session by ID")

	return cmd
}

func runChat(cmd *cobra.Command, args []string) error {
	workspace, _ := cmd.Flags().GetString("workspace")
	if workspace == "" {
		workspace = "default"
	}

	// TODO: Connect to gateway SSE endpoint once server is implemented.
	if len(args) > 0 {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "[%s] You: %s\n", workspace, args[0])
		return err
	}

	_, err := fmt.Fprintf(cmd.OutOrStdout(), "Interactive chat in workspace %q (not yet implemented)\n", workspace)
	return err
}

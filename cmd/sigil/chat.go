// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"encoding/json"
	"fmt"
	"strings"

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
	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runChat(cmd *cobra.Command, args []string) error {
	workspace, _ := cmd.Flags().GetString("workspace")
	if workspace == "" {
		workspace = "default"
	}

	if len(args) == 0 {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Interactive chat in workspace %q (connect to gateway SSE endpoint)\n", workspace)
		return err
	}

	addr, _ := cmd.Flags().GetString("address")
	model, _ := cmd.Flags().GetString("model")
	sessionID, _ := cmd.Flags().GetString("session")

	return streamChat(cmd, addr, chatRequest{
		Content:     strings.Join(args, " "),
		WorkspaceID: workspace,
		SessionID:   sessionID,
		Model:       model,
	})
}

// chatRequest is the request body sent to the gateway's chat/stream endpoint.
type chatRequest struct {
	Content     string `json:"content"`
	WorkspaceID string `json:"workspace_id"`
	SessionID   string `json:"session_id,omitempty"`
	Model       string `json:"model,omitempty"`
}

// streamChat connects to the gateway SSE endpoint, streams text_delta events
// to stdout and error events to stderr.
func streamChat(cmd *cobra.Command, addr string, req chatRequest) error {
	gw := newGatewayClient(addr)

	events, err := gw.postSSE("/api/v1/chat/stream", req)
	if err != nil {
		return err
	}

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	for ev := range events {
		switch ev.Event {
		case "text_delta":
			var delta struct {
				Text string `json:"text"`
			}
			if jsonErr := json.Unmarshal([]byte(ev.Data), &delta); jsonErr == nil {
				_, _ = fmt.Fprint(stdout, delta.Text)
			}
		case "error":
			var errData struct {
				Message string `json:"message"`
			}
			if jsonErr := json.Unmarshal([]byte(ev.Data), &errData); jsonErr == nil {
				_, _ = fmt.Fprintf(stderr, "Error: %s\n", errData.Message)
			} else {
				_, _ = fmt.Fprintf(stderr, "Error: %s\n", ev.Data)
			}
		case "done":
			// Stream complete.
		}
	}

	return nil
}

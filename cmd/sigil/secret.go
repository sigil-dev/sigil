// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

// serviceName is the keyring service name under which Sigil stores secrets.
const serviceName = "sigil"

// secretStoreFactory creates a secrets.Store. It is a package-level variable
// so tests can substitute a mock implementation.
var secretStoreFactory = func() secrets.Store {
	return secrets.NewKeyringStore()
}

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets stored in the OS keyring",
		Long:  "List and delete secrets stored under the Sigil service in the operating system keyring.",
	}

	cmd.AddCommand(
		newSecretListCmd(),
		newSecretDeleteCmd(),
	)

	return cmd
}

func newSecretListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all stored secret names",
		RunE:  runSecretList,
	}
}

func newSecretDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a secret by name",
		Args:  cobra.ExactArgs(1),
		RunE:  runSecretDelete,
	}
}

func runSecretList(cmd *cobra.Command, _ []string) error {
	store := secretStoreFactory()
	keys, err := store.List(serviceName)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeSecretListFailure, "listing secrets: %w", err)
	}

	out := cmd.OutOrStdout()
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(out, "No secrets stored.")
		return nil
	}

	for _, k := range keys {
		_, _ = fmt.Fprintln(out, k)
	}
	return nil
}

func runSecretDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	store := secretStoreFactory()

	if err := store.Delete(serviceName, name); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeSecretNotFound) {
			return sigilerr.Errorf(sigilerr.CodeSecretNotFound, "secret %q not found", name)
		}
		return sigilerr.Errorf(sigilerr.CodeSecretDeleteFailure, "deleting secret %q: %w", name, err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted secret: %s\n", name)
	return nil
}

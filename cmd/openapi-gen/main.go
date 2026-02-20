// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

func main() {
	spec, err := generateSpec()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outPath := "api/openapi/spec.json"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output dir: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, spec, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing spec: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OpenAPI spec written to %s\n", outPath)
}

// generateSpec creates a server with all routes registered and extracts the
// OpenAPI spec that huma generates from the Go type annotations.
func generateSpec() ([]byte, error) {
	// Use no-op service stubs so all routes are registered for schema
	// discovery. Handlers are never invoked during spec generation.
	svc := server.NewServicesForTest(&stubWorkspace{}, &stubPlugin{}, &stubSession{}, &stubUser{})

	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		Services:   svc,
	})
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating server: %w", err)
	}

	return json.MarshalIndent(srv.API().OpenAPI(), "", "  ")
}

// No-op service stubs for spec generation. Methods are never called.

type stubWorkspace struct{}

func (s *stubWorkspace) List(context.Context) ([]server.WorkspaceSummary, error) { return nil, nil }
func (s *stubWorkspace) ListForUser(context.Context, string) ([]server.WorkspaceSummary, error) {
	return nil, nil
}

func (s *stubWorkspace) Get(context.Context, string) (*server.WorkspaceDetail, error) {
	return nil, nil
}

type stubPlugin struct{}

func (s *stubPlugin) List(context.Context) ([]server.PluginSummary, error) { return nil, nil }
func (s *stubPlugin) Get(context.Context, string) (*server.PluginDetail, error) {
	return nil, nil
}
func (s *stubPlugin) Reload(context.Context, string) error { return nil }

type stubSession struct{}

func (s *stubSession) List(context.Context, string) ([]server.SessionSummary, error) {
	return nil, nil
}

func (s *stubSession) Get(context.Context, string, string) (*server.SessionDetail, error) {
	return nil, nil
}

type stubUser struct{}

func (s *stubUser) List(context.Context) ([]server.UserSummary, error) { return nil, nil }

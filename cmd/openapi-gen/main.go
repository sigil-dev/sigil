// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigil-dev/sigil/internal/server"
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

	if err := os.MkdirAll("api/openapi", 0o755); err != nil {
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
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}

	// Register routes with nil services — we only need the spec, not working handlers.
	srv.RegisterServices(&server.Services{})

	return json.MarshalIndent(srv.API().OpenAPI(), "", "  ")
}

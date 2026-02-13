// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand_Help(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"--help"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "sigil")
	assert.Contains(t, buf.String(), "start")
	assert.Contains(t, buf.String(), "status")
	assert.Contains(t, buf.String(), "version")
}

func TestVersionCommand(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"version"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "sigil")
}

func TestStartCommand_RequiresConfig(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"start", "--config", "/nonexistent/path.yaml"})

	err := root.Execute()
	assert.Error(t, err)
}

func TestRootCommand_GlobalFlags(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"--verbose", "--help"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "--config")
	assert.Contains(t, buf.String(), "--data-dir")
	assert.Contains(t, buf.String(), "--verbose")
}

func TestStatusCommand_Help(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"status", "--help"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "status")
}

func TestStatusCommand_HealthyGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	old := statusClient
	statusClient = srv.Client()
	defer func() { statusClient = old }()

	// Extract host:port from test server URL (strip "http://").
	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"status", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "ok")
}

func TestStatusCommand_GatewayDown(t *testing.T) {
	// Use an address that will refuse connections.
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"status", "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "not running")
}

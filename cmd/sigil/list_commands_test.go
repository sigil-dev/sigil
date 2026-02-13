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

// testSetupGateway starts a mock gateway, overrides defaultHTTPClient,
// and returns a cleanup function and the server address (host:port).
func testSetupGateway(t *testing.T, handler http.Handler) (addr string, cleanup func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	addr = srv.URL[len("http://"):]
	cleanup = func() {
		defaultHTTPClient = old
		srv.Close()
	}
	return addr, cleanup
}

// --- Workspace List ---

func TestWorkspaceList_Success(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/workspaces" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"workspaces": []map[string]string{
				{"id": "ws-1", "description": "Default workspace"},
				{"id": "ws-2", "description": "Testing"},
			},
		})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"workspace", "list", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "DESCRIPTION")
	assert.Contains(t, output, "ws-1")
	assert.Contains(t, output, "Default workspace")
	assert.Contains(t, output, "ws-2")
	assert.Contains(t, output, "Testing")
}

func TestWorkspaceList_Empty(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"workspaces": []interface{}{}})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"workspace", "list", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No workspaces found")
}

func TestWorkspaceList_ConnRefused(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"workspace", "list", "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "not running")
}

// --- Plugin List ---

func TestPluginList_Success(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/plugins" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"plugins": []map[string]string{
				{"name": "anthropic", "type": "provider", "version": "1.0.0", "status": "running"},
				{"name": "web-search", "type": "tool", "version": "0.2.1", "status": "stopped"},
			},
		})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"plugin", "list", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "TYPE")
	assert.Contains(t, output, "VERSION")
	assert.Contains(t, output, "STATUS")
	assert.Contains(t, output, "anthropic")
	assert.Contains(t, output, "provider")
	assert.Contains(t, output, "1.0.0")
	assert.Contains(t, output, "running")
	assert.Contains(t, output, "web-search")
}

func TestPluginList_Empty(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"plugins": []interface{}{}})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"plugin", "list", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No plugins found")
}

func TestPluginList_ConnRefused(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"plugin", "list", "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "not running")
}

// --- Session List ---

func TestSessionList_Success(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/workspaces/ws-1/sessions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessions": []map[string]string{
				{"id": "sess-1", "workspace_id": "ws-1", "status": "active"},
				{"id": "sess-2", "workspace_id": "ws-1", "status": "archived"},
			},
		})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"session", "list", "--workspace", "ws-1", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "WORKSPACE")
	assert.Contains(t, output, "STATUS")
	assert.Contains(t, output, "sess-1")
	assert.Contains(t, output, "ws-1")
	assert.Contains(t, output, "active")
	assert.Contains(t, output, "sess-2")
	assert.Contains(t, output, "archived")
}

func TestSessionList_RequiresWorkspace(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"session", "list"})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace")
}

func TestSessionList_Empty(t *testing.T) {
	addr, cleanup := testSetupGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"sessions": []interface{}{}})
	}))
	defer cleanup()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"session", "list", "--workspace", "ws-1", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No sessions found")
}

func TestSessionList_ConnRefused(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"session", "list", "--workspace", "ws-1", "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "not running")
}

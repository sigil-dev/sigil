// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const defaultQueueTTL = 60 * time.Second

const (
	maxArgsSizeBytes  = 64 * 1024 // 64 KB
	maxPendingPerNode = 100
)

// Authenticator validates node identity during registration.
type Authenticator interface {
	Authenticate(reg Registration) error
}

// WorkspaceValidator checks whether a node is permitted to bind to a workspace.
type WorkspaceValidator interface {
	ValidateWorkspace(nodeID, workspaceID string) error
}

type Registration struct {
	NodeID        string
	WorkspaceID   string
	Platform      string
	Capabilities  []string
	TailscaleTags []string // for Tailscale tag-based auth
	AuthToken     string   // for token-based auth
	Tools         []string
}

type Node struct {
	ID           string
	WorkspaceID  string
	Platform     string
	Capabilities []string
	Tools        []string
	Online       bool
}

type PendingRequest struct {
	ID        string
	NodeID    string
	Tool      string
	Args      string
	QueuedAt  time.Time
	ExpiresAt time.Time
}

type ManagerConfig struct {
	QueueTTL           time.Duration
	CleanupInterval    time.Duration // interval for background expired-request cleanup; 0 = disabled
	Now                func() time.Time
	Auth               Authenticator      // optional; nil means no auth required
	WorkspaceValidator WorkspaceValidator // optional; nil means no workspace enforcement
}

type Manager struct {
	mu sync.RWMutex

	nodes   map[string]Node
	pending map[string][]PendingRequest

	queueTTL           time.Duration
	now                func() time.Time
	nextID             uint64
	auth               Authenticator
	workspaceValidator WorkspaceValidator

	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewManager(cfg ManagerConfig) *Manager {
	queueTTL := cfg.QueueTTL
	if queueTTL <= 0 {
		queueTTL = defaultQueueTTL
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	m := &Manager{
		nodes:              make(map[string]Node),
		pending:            make(map[string][]PendingRequest),
		queueTTL:           queueTTL,
		now:                now,
		auth:               cfg.Auth,
		workspaceValidator: cfg.WorkspaceValidator,
		stopCh:             make(chan struct{}),
	}

	if cfg.CleanupInterval > 0 {
		go m.cleanupLoop(cfg.CleanupInterval)
	}

	return m
}

// Stop stops the background cleanup goroutine if one was started. Safe to call
// multiple times and on managers created without a CleanupInterval.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

// cleanupLoop periodically prunes fully-expired pending queues to prevent map
// key accumulation for offline nodes that never call QueueToolCall again.
func (m *Manager) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("cleanupLoop panic recovered", "panic", r, "package", "node")
					}
				}()
				m.mu.Lock()
				defer m.mu.Unlock()
				now := m.now()
				for nodeID := range m.pending {
					m.pruneExpiredLocked(nodeID, now)
				}
			}()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) Register(reg Registration) error {
	nodeID := strings.TrimSpace(reg.NodeID)
	if nodeID == "" {
		return sigilerr.New(sigilerr.CodeServerRequestInvalid, "node id is required")
	}

	if m.auth != nil {
		if err := m.auth.Authenticate(reg); err != nil {
			slog.Warn("node authentication failed", "node_id", nodeID, "error", err)
			return sigilerr.Wrapf(err, sigilerr.CodeServerAuthUnauthorized, "authenticating node %s", nodeID)
		}
	}

	if m.workspaceValidator != nil {
		if err := m.workspaceValidator.ValidateWorkspace(nodeID, reg.WorkspaceID); err != nil {
			slog.Warn("node workspace validation failed", "node_id", nodeID, "workspace_id", reg.WorkspaceID, "error", err)
			return sigilerr.Wrapf(err, sigilerr.CodeServerAuthUnauthorized, "validating workspace for node %s", nodeID)
		}
	}

	tools := make([]string, len(reg.Tools))
	copy(tools, reg.Tools)

	caps := make([]string, len(reg.Capabilities))
	copy(caps, reg.Capabilities)

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.nodes[nodeID]; ok {
		if existing.Online {
			return sigilerr.New(sigilerr.CodeServerRequestInvalid, "node is already online; disconnect before re-registering",
				sigilerr.Field("node_id", nodeID))
		}
		slog.Warn("offline node re-registering", "node_id", nodeID, "previous_workspace", existing.WorkspaceID)
	}

	m.nodes[nodeID] = Node{
		ID:           nodeID,
		WorkspaceID:  reg.WorkspaceID,
		Platform:     reg.Platform,
		Capabilities: caps,
		Tools:        tools,
		Online:       true,
	}

	return nil
}

func (m *Manager) PrefixedTools(nodeID string) ([]string, error) {
	m.mu.RLock()
	node, ok := m.nodes[nodeID]
	m.mu.RUnlock()
	if !ok {
		slog.Warn("prefixed tools: node not found", "node_id", nodeID)
		return nil, sigilerr.New(sigilerr.CodeServerEntityNotFound, "node not found",
			sigilerr.Field("node_id", nodeID))
	}

	tools := make([]string, len(node.Tools))
	for i, tool := range node.Tools {
		tools[i] = "node:" + nodeID + ":" + tool
	}

	return tools, nil
}

func (m *Manager) Disconnect(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		slog.Warn("Disconnect: node not found", "node_id", nodeID)
		return sigilerr.New(sigilerr.CodeServerEntityNotFound, "node not found",
			sigilerr.Field("node_id", nodeID))
	}

	node.Online = false
	m.nodes[nodeID] = node
	return nil
}

func (m *Manager) List() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.nodes))
	for id := range m.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	nodes := make([]Node, 0, len(ids))
	for _, id := range ids {
		node := m.nodes[id]
		node.Capabilities = append([]string(nil), node.Capabilities...)
		node.Tools = append([]string(nil), node.Tools...)
		nodes = append(nodes, node)
	}

	return nodes
}

func (m *Manager) QueueToolCall(nodeID, tool, args string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "node id is required")
	}

	tool = strings.TrimSpace(tool)
	if tool == "" {
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "tool is required")
	}

	if len(args) > maxArgsSizeBytes {
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "args payload exceeds maximum size",
			sigilerr.Field("node_id", nodeID), sigilerr.Field("size", len(args)))
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		slog.Warn("QueueToolCall: node not found", "node_id", nodeID)
		return "", sigilerr.New(sigilerr.CodeServerEntityNotFound, "node not found",
			sigilerr.Field("node_id", nodeID))
	}
	if node.Online {
		slog.Warn("QueueToolCall: node is online, cannot queue", "node_id", nodeID)
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "node is online; queueing is only for offline nodes",
			sigilerr.Field("node_id", nodeID))
	}
	if !slices.Contains(node.Tools, tool) {
		slog.Warn("QueueToolCall: tool not registered on node", "node_id", nodeID, "tool", tool)
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "tool is not registered on node",
			sigilerr.Field("node_id", nodeID),
			sigilerr.Field("tool", tool))
	}

	now := m.now()
	m.pruneExpiredLocked(nodeID, now)

	if len(m.pending[nodeID]) >= maxPendingPerNode {
		slog.Warn("QueueToolCall: pending queue full", "node_id", nodeID, "queue_size", maxPendingPerNode)
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "pending queue is full for node",
			sigilerr.Field("node_id", nodeID))
	}

	m.nextID++
	requestID := fmt.Sprintf("req-%d", m.nextID)
	m.pending[nodeID] = append(m.pending[nodeID], PendingRequest{
		ID:        requestID,
		NodeID:    nodeID,
		Tool:      tool,
		Args:      args,
		QueuedAt:  now,
		ExpiresAt: now.Add(m.queueTTL),
	})

	return requestID, nil
}

func (m *Manager) PendingRequests(nodeID string) ([]PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.nodes[nodeID]; !ok {
		slog.Debug("PendingRequests: node not found", "node_id", nodeID)
		return nil, sigilerr.New(sigilerr.CodeServerEntityNotFound, "node not found",
			sigilerr.Field("node_id", nodeID))
	}

	now := m.now()
	queued := m.pending[nodeID]
	out := make([]PendingRequest, 0, len(queued))
	for _, req := range queued {
		if !req.ExpiresAt.Before(now) {
			out = append(out, req)
		}
	}
	return out, nil
}

func (m *Manager) pruneExpiredLocked(nodeID string, now time.Time) {
	queued := m.pending[nodeID]
	if len(queued) == 0 {
		return
	}

	keep := queued[:0]
	for _, req := range queued {
		if !req.ExpiresAt.Before(now) {
			keep = append(keep, req)
		}
	}

	if len(keep) == 0 {
		delete(m.pending, nodeID)
		return
	}

	// Copy to a fresh allocation to release the backing array held by expired entries.
	copied := make([]PendingRequest, len(keep))
	copy(copied, keep)
	m.pending[nodeID] = copied
}

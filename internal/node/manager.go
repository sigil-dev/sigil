// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const defaultQueueTTL = 60 * time.Second

type Registration struct {
	NodeID string
	Tools  []string
}

type Node struct {
	ID     string
	Tools  []string
	Online bool
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
	QueueTTL time.Duration
	Now      func() time.Time
}

type Manager struct {
	mu sync.RWMutex

	nodes   map[string]Node
	pending map[string][]PendingRequest

	queueTTL time.Duration
	now      func() time.Time
	nextID   uint64
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

	return &Manager{
		nodes:    make(map[string]Node),
		pending:  make(map[string][]PendingRequest),
		queueTTL: queueTTL,
		now:      now,
	}
}

func (m *Manager) Register(reg Registration) error {
	nodeID := strings.TrimSpace(reg.NodeID)
	if nodeID == "" {
		return sigilerr.New(sigilerr.CodeServerRequestInvalid, "node id is required")
	}

	tools := make([]string, len(reg.Tools))
	copy(tools, reg.Tools)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[nodeID] = Node{
		ID:     nodeID,
		Tools:  tools,
		Online: true,
	}

	return nil
}

func (m *Manager) PrefixedTools(nodeID string) []string {
	m.mu.RLock()
	node, ok := m.nodes[nodeID]
	m.mu.RUnlock()
	if !ok {
		return nil
	}

	tools := make([]string, len(node.Tools))
	for i, tool := range node.Tools {
		tools[i] = "node:" + nodeID + ":" + tool
	}

	return tools
}

func (m *Manager) Disconnect(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return
	}

	node.Online = false
	m.nodes[nodeID] = node
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

	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return "", sigilerr.New(sigilerr.CodeServerEntityNotFound, "node not found",
			sigilerr.Field("node_id", nodeID))
	}
	if node.Online {
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "node is online; queueing is only for offline nodes",
			sigilerr.Field("node_id", nodeID))
	}
	if !slices.Contains(node.Tools, tool) {
		return "", sigilerr.New(sigilerr.CodeServerRequestInvalid, "tool is not registered on node",
			sigilerr.Field("node_id", nodeID),
			sigilerr.Field("tool", tool))
	}

	now := m.now()
	m.pruneExpiredLocked(nodeID, now)

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

func (m *Manager) PendingRequests(nodeID string) []PendingRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.now()
	queued := m.pending[nodeID]
	out := make([]PendingRequest, 0, len(queued))
	for _, req := range queued {
		if !req.ExpiresAt.Before(now) {
			out = append(out, req)
		}
	}
	return out
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
	m.pending[nodeID] = keep
}

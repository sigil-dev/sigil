// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/sigil-dev/sigil/internal/security"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

type Manager struct {
	mu         sync.RWMutex
	pluginsDir string
	enforcer   *security.Enforcer
	plugins    map[string]*Instance
}

func NewManager(pluginsDir string, enforcer *security.Enforcer) *Manager {
	return &Manager{
		pluginsDir: pluginsDir,
		enforcer:   enforcer,
		plugins:    make(map[string]*Instance),
	}
}

func (m *Manager) Discover(ctx context.Context) ([]*Manifest, error) {
	entries, err := os.ReadDir(m.pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, sigilerr.Wrap(err, sigilerr.CodePluginDiscoveryFailure, "reading plugins directory")
	}

	var manifests []*Manifest

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		manifestPath := filepath.Join(m.pluginsDir, entry.Name(), "plugin.yaml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			if !os.IsNotExist(err) {
				slog.Warn("skipping plugin: cannot read manifest",
					"path", manifestPath, "error", err)
			}
			continue
		}

		manifest, err := ParseManifest(data)
		if err != nil {
			slog.Warn("skipping plugin: invalid manifest",
				"path", manifestPath, "error", err)
			continue
		}

		allowCaps := security.NewCapabilitySet(manifest.Capabilities...)
		denyCaps := security.NewCapabilitySet(manifest.DenyCapabilities...)

		if m.enforcer != nil {
			m.enforcer.RegisterPlugin(manifest.Name, allowCaps, denyCaps)
		}

		m.mu.Lock()
		m.plugins[manifest.Name] = NewInstance(manifest.Name, StateDiscovered)
		m.mu.Unlock()

		manifests = append(manifests, manifest)
	}

	return manifests, nil
}

func (m *Manager) Get(name string) (*Instance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inst, ok := m.plugins[name]
	if !ok {
		return nil, sigilerr.Errorf(sigilerr.CodePluginNotFound, "plugin %q not found", name)
	}

	return inst, nil
}

func (m *Manager) List() []*Instance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Instance, 0, len(m.plugins))
	for _, inst := range m.plugins {
		list = append(list, inst)
	}

	return list
}

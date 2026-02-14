// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	seenNames := make(map[string]string) // manifest.Name -> directory path

	for _, entry := range entries {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, sigilerr.Wrap(ctx.Err(), sigilerr.CodePluginDiscoveryFailure, "discovery cancelled")
		default:
		}

		if !entry.IsDir() {
			continue
		}

		dirPath := entry.Name()
		manifestPath := filepath.Join(m.pluginsDir, dirPath, "plugin.yaml")
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

		// Detect duplicate plugin names
		if prevPath, exists := seenNames[manifest.Name]; exists {
			slog.Warn("duplicate plugin name detected; last-wins behavior applies",
				"plugin_name", manifest.Name,
				"first_path", prevPath,
				"second_path", dirPath)
		}
		seenNames[manifest.Name] = dirPath

		allowCaps := security.NewCapabilitySet(manifest.Capabilities...)
		denyCaps := security.NewCapabilitySet(manifest.DenyCapabilities...)

		if m.enforcer != nil {
			m.enforcer.RegisterPlugin(manifest.Name, allowCaps, denyCaps)
		}

		m.mu.Lock()
		m.plugins[manifest.Name] = NewInstanceFromConfig(InstanceConfig{
			Name:         manifest.Name,
			Type:         string(manifest.Type),
			Version:      manifest.Version,
			Tier:         string(manifest.Execution.Tier),
			Capabilities: manifest.Capabilities,
			InitialState: StateDiscovered,
		})
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

	// Sort by plugin name for deterministic ordering
	slices.SortFunc(list, func(a, b *Instance) int {
		aName := a.Name()
		bName := b.Name()
		if aName < bName {
			return -1
		}
		if aName > bName {
			return 1
		}
		return 0
	})

	return list
}

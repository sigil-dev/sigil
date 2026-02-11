// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkillLoader_ParseSkill(t *testing.T) {
	path := filepath.Join("testdata", "test-skill", "SKILL.md")

	skill, err := agent.ParseSkillFile(path)
	require.NoError(t, err)

	assert.Equal(t, "test-skill", skill.Name)
	assert.Equal(t, "A test skill for unit tests", skill.Description)
	assert.Equal(t, "MIT", skill.License)

	assert.Equal(t, "test", skill.Metadata["author"])
	assert.Equal(t, "1.0", skill.Metadata["version"])
	assert.Equal(t, "auto", skill.Metadata["gateway:trigger"])
	assert.Equal(t, "test example", skill.Metadata["gateway:keywords"])
	assert.Equal(t, "test-ws", skill.Metadata["gateway:workspace"])

	assert.Contains(t, skill.Content, "You are a test skill that helps with testing.")
	assert.Contains(t, skill.Content, "## Instructions")
	assert.Contains(t, skill.Content, "Always respond with \"test response\"")
}

func TestSkillLoader_LoadFromDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create two skill subdirectories.
	for _, name := range []string{"skill-a", "skill-b"} {
		skillDir := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(skillDir, 0o755))

		content := "---\nname: " + name + "\ndescription: " + name + " desc\nlicense: MIT\nmetadata:\n  author: test\n---\n\nBody for " + name + "\n"
		require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o644))
	}

	skills, err := agent.LoadSkills(dir)
	require.NoError(t, err)
	assert.Len(t, skills, 2)

	names := make(map[string]bool)
	for _, s := range skills {
		names[s.Name] = true
	}
	assert.True(t, names["skill-a"])
	assert.True(t, names["skill-b"])
}

func TestSkillLoader_TriggerMode(t *testing.T) {
	tests := []struct {
		name     string
		trigger  string
		expected agent.TriggerMode
	}{
		{"auto trigger", "auto", agent.TriggerAuto},
		{"manual trigger", "manual", agent.TriggerManual},
		{"keyword trigger", "keyword", agent.TriggerKeyword},
		{"empty defaults to manual", "", agent.TriggerManual},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &agent.Skill{
				Metadata: map[string]string{
					"gateway:trigger": tt.trigger,
				},
			}
			assert.Equal(t, tt.expected, s.TriggerMode())
		})
	}
}

func TestSkillLoader_KeywordMatch(t *testing.T) {
	s := &agent.Skill{
		Metadata: map[string]string{
			"gateway:keywords": "kubernetes terraform deploy",
		},
	}

	tests := []struct {
		name  string
		text  string
		match bool
	}{
		{"matches kubernetes", "deploy the kubernetes cluster", true},
		{"matches terraform", "run terraform plan", true},
		{"no match", "what is the weather", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, s.MatchesKeyword(tt.text))
		})
	}
}

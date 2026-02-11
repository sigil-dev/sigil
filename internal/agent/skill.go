// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TriggerMode defines how a skill is activated.
type TriggerMode int

const (
	TriggerManual  TriggerMode = iota // default — explicit invocation
	TriggerAuto                       // injected into every prompt
	TriggerKeyword                    // activated when keywords match
)

// Skill represents a loaded agentskills.io skill.
type Skill struct {
	Name        string
	Description string
	License     string
	Metadata    map[string]string
	Content     string // Markdown body after frontmatter
}

// skillFrontmatter is the intermediate struct for YAML parsing.
type skillFrontmatter struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	License     string            `yaml:"license"`
	Metadata    map[string]string `yaml:"metadata"`
}

// ParseSkillFile reads a SKILL.md file and returns a parsed Skill.
// The file must contain YAML frontmatter delimited by "---" lines,
// followed by the markdown body.
func ParseSkillFile(path string) (*Skill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// Split frontmatter from body. Expect leading "---\n" and closing "---\n".
	if !strings.HasPrefix(content, "---\n") {
		return nil, fmt.Errorf("skill file %s: missing opening frontmatter delimiter", path)
	}

	// Find the closing delimiter after the opening one.
	rest := content[4:] // skip opening "---\n"
	idx := strings.Index(rest, "\n---\n")
	if idx < 0 {
		return nil, fmt.Errorf("skill file %s: missing closing frontmatter delimiter", path)
	}

	frontmatterRaw := rest[:idx]
	body := rest[idx+5:] // skip "\n---\n"

	var fm skillFrontmatter
	if err := yaml.Unmarshal([]byte(frontmatterRaw), &fm); err != nil {
		return nil, fmt.Errorf("skill file %s: parsing frontmatter: %w", path, err)
	}

	return &Skill{
		Name:        fm.Name,
		Description: fm.Description,
		License:     fm.License,
		Metadata:    fm.Metadata,
		Content:     body,
	}, nil
}

// LoadSkills scans dir for subdirectories containing a SKILL.md file
// and returns all parsed skills.
func LoadSkills(dir string) ([]*Skill, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var skills []*Skill
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		skillFile := filepath.Join(dir, entry.Name(), "SKILL.md")
		if _, err := os.Stat(skillFile); err != nil {
			continue // no SKILL.md in this subdirectory
		}

		skill, err := ParseSkillFile(skillFile)
		if err != nil {
			return nil, err
		}
		skills = append(skills, skill)
	}

	return skills, nil
}

// TriggerMode reads the "gateway:trigger" metadata value and returns
// the corresponding TriggerMode.
func (s *Skill) TriggerMode() TriggerMode {
	switch s.Metadata["gateway:trigger"] {
	case "auto":
		return TriggerAuto
	case "keyword":
		return TriggerKeyword
	default:
		return TriggerManual
	}
}

// MatchesKeyword splits the "gateway:keywords" metadata by spaces and
// returns true if any keyword appears as a case-insensitive substring of text.
func (s *Skill) MatchesKeyword(text string) bool {
	raw := s.Metadata["gateway:keywords"]
	if raw == "" {
		return false
	}

	lower := strings.ToLower(text)
	for _, kw := range strings.Fields(raw) {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}

	return false
}

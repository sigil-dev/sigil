---
description: Scaffold a new Sigil plugin with manifest, implementation, and tests
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(task *), Bash(mkdir *)
---

# Scaffold New Plugin

Create a new Sigil plugin with the correct structure.

Ask the user (if not provided via $ARGUMENTS):
1. **Plugin type**: provider, channel, tool, or skill
2. **Plugin name**: lowercase, hyphenated (e.g., `telegram`, `web-search`)
3. **Execution tier**: wasm, process, or container
4. **Capabilities needed**: what the plugin needs access to

Then create:

1. `plugins/<name>/plugin.yaml` — manifest with:
   - name, version, type, description
   - execution tier
   - capabilities list
   - config_schema (if applicable)

2. `plugins/<name>/main.go` — implementation skeleton with:
   - Correct gRPC service interface for the plugin type
   - go-plugin ServeConfig
   - Placeholder methods with TODO comments

3. `plugins/<name>/main_test.go` — test skeleton with:
   - Table-driven test structure
   - Mock gRPC client setup

Reference `docs/design/02-plugin-system.md` for manifest format and gRPC contracts.

$ARGUMENTS

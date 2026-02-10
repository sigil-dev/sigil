# Phase 7: UI & Distribution

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the SvelteKit web UI, Tauri desktop wrapper, GoReleaser configuration, and documentation site. After this phase, Sigil is a complete, distributable product.

**Architecture:** SvelteKit talks to the gateway via REST+SSE using a TypeScript client generated from the OpenAPI spec. Tauri wraps the SvelteKit app and bundles the gateway binary as a sidecar process. GoReleaser handles cross-platform builds with CGo. Zensical builds the documentation site.

**Tech Stack:** SvelteKit, TypeScript, openapi-typescript, openapi-fetch, Tauri v2, GoReleaser, Zensical (uv), Cosign, Syft

**Design Docs:**

- [Section 9: UI and CLI](../design/09-ui-and-cli.md) — SvelteKit UI areas, Tauri desktop, first-run experience
- [Section 10: Build and Distribution](../design/10-build-and-distribution.md) — GoReleaser, distribution channels, toolchain

**Depends on:** Phase 5 (REST+SSE endpoints, OpenAPI spec). Can run in parallel with Phase 6.

---

## Task 1: SvelteKit Project Setup + API Client Generation

**Files:**

- Create: `ui/package.json`
- Create: `ui/svelte.config.js`
- Create: `ui/src/lib/api/client.ts`
- Create: `ui/src/routes/+layout.svelte`

**Step 1: Initialize SvelteKit project**

```bash
cd ui
npx sv create . --template minimal --types ts
npm install
npm install openapi-typescript openapi-fetch
```

**Step 2: Generate TypeScript client from OpenAPI spec**

Add script to `ui/package.json`:

```json
{
  "scripts": {
    "generate:api": "openapi-typescript ../api/openapi/spec.yaml -o src/lib/api/generated/schema.d.ts",
    "dev": "vite dev",
    "build": "vite build",
    "check": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json"
  }
}
```

Run: `npm run generate:api`

Expected: `ui/src/lib/api/generated/schema.d.ts` is created.

**Step 3: Create API client wrapper**

`ui/src/lib/api/client.ts`:

```typescript
import createClient from 'openapi-fetch';
import type { paths } from './generated/schema';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:18789';

export const api = createClient<paths>({
  baseUrl: API_BASE,
});
```

**Step 4: Verify build**

```bash
cd ui && npm run check
```

Expected: No TypeScript errors.

**Step 5: Commit**

```bash
git add ui/
git commit -m "feat(ui): initialize SvelteKit project with OpenAPI client generation"
```

---

## Task 2: Chat UI

**Files:**

- Create: `ui/src/routes/chat/+page.svelte`
- Create: `ui/src/routes/chat/+page.ts`
- Create: `ui/src/lib/components/ChatMessage.svelte`
- Create: `ui/src/lib/components/ChatInput.svelte`
- Create: `ui/src/lib/stores/chat.ts`

**Step 1: Build chat store**

`ui/src/lib/stores/chat.ts` — Svelte store managing:

- Current session ID
- Messages array
- Loading state
- SSE connection for streaming responses
- `sendMessage(content: string)` function that POSTs to `/api/v1/chat/stream` and reads SSE events

**Step 2: Build chat components**

- `ChatMessage.svelte` — renders a single message (user/assistant/tool), shows tool calls with expandable results
- `ChatInput.svelte` — text input with submit button, shows loading spinner during streaming

**Step 3: Build chat page**

`ui/src/routes/chat/+page.svelte`:

- Session sidebar (grouped by workspace)
- Conversation view with streaming responses
- Tool call visualization (name, status, expandable results)
- Message input with send button

**Step 4: Verify**

```bash
cd ui && npm run check && npm run build
```

Expected: Build succeeds with no errors.

**Step 5: Commit**

```bash
git add ui/src/
git commit -m "feat(ui): add chat interface with streaming SSE responses"
```

---

## Task 3: Workspace, Plugin, and Settings UI

**Files:**

- Create: `ui/src/routes/workspaces/+page.svelte`
- Create: `ui/src/routes/workspaces/[id]/+page.svelte`
- Create: `ui/src/routes/plugins/+page.svelte`
- Create: `ui/src/routes/settings/+page.svelte`

**Step 1: Workspace pages**

- List view: workspace cards showing members, model, channels, nodes, tools, budget
- Detail view: skill management, tool allowlist config, channel/node bindings

**Step 2: Plugin pages**

- Plugin list with status indicators (running/stopped/error)
- Execution tier badge (wasm/process/container)
- Per-plugin actions: logs, reload, remove, inspect manifest

**Step 3: Settings page**

- Provider configuration (API keys, endpoints)
- Global settings (networking mode, default model, budgets)
- User management and pairing
- Audit log viewer (table with filtering)

**Step 4: Verify**

```bash
cd ui && npm run check && npm run build
```

**Step 5: Commit**

```bash
git add ui/src/routes/
git commit -m "feat(ui): add workspace, plugin, and settings pages"
```

---

## Task 4: Tauri Desktop App

**Files:**

- Create: `ui/src-tauri/tauri.conf.json`
- Create: `ui/src-tauri/src/main.rs`
- Create: `ui/src-tauri/Cargo.toml`

**Step 1: Initialize Tauri in the UI project**

```bash
cd ui
npm install @tauri-apps/cli @tauri-apps/api
npx tauri init
```

**Step 2: Configure sidecar**

`ui/src-tauri/tauri.conf.json` — key settings:

```json
{
  "build": {
    "beforeBuildCommand": "npm run build",
    "beforeDevCommand": "npm run dev",
    "devUrl": "http://localhost:5173",
    "frontendDist": "../build"
  },
  "app": {
    "windows": [
      {
        "title": "Sigil",
        "width": 1200,
        "height": 800
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "identifier": "dev.sigil.app",
    "icon": ["icons/icon.png"]
  },
  "plugins": {
    "shell": {
      "sidecar": true,
      "scope": [
        {
          "name": "sigil",
          "cmd": "binaries/sigil",
          "args": ["start", "--config", "$APPDATA/sigil/sigil.yaml"]
        }
      ]
    }
  }
}
```

**Step 3: System tray**

`ui/src-tauri/src/main.rs` — configure:

- System tray icon with status indicator
- Quick actions: Open UI, Pause Agent, Restart, Quit
- Auto-launch gateway sidecar on app start
- Auto-update via Tauri updater

**Step 4: Verify**

```bash
cd ui && npx tauri build --debug
```

Expected: Debug build produces an app bundle.

**Step 5: Commit**

```bash
git add ui/src-tauri/
git commit -m "feat(ui): add Tauri desktop wrapper with sidecar and system tray"
```

---

## Task 5: GoReleaser Configuration

**Files:**

- Create: `.goreleaser.yaml`

**Step 1: Write GoReleaser config**

```yaml
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors

version: 2

project_name: sigil

before:
  hooks:
    - task generate

builds:
  # Main binary (CGO_ENABLED=1 for sqlite3/sqlite-vec)
  - id: sigil
    main: ./cmd/sigil
    binary: sigil
    env:
      - CGO_ENABLED=1
    goos:
      - linux
      - darwin
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.ShortCommit}}
      - -X main.date={{.Date}}

archives:
  - id: sigil
    builds:
      - sigil
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

checksum:
  name_template: checksums.txt
  algorithm: sha256

sboms:
  - artifacts: archive
    cmd: syft
    args:
      - "${artifact}"
      - "--output"
      - "cyclonedx-json=${document}"
    documents:
      - "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}.sbom.cdx.json"
  - id: spdx
    artifacts: archive
    cmd: syft
    args:
      - "${artifact}"
      - "--output"
      - "spdx-json=${document}"
    documents:
      - "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}.sbom.spdx.json"

signs:
  - cmd: cosign
    env:
      - COSIGN_EXPERIMENTAL=1
    artifacts: checksum
    output: true
    args:
      - sign-blob
      - "--yes"
      - "--output-certificate=${certificate}"
      - "--output-signature=${signature}"
      - "${artifact}"

changelog:
  use: github-native

brews:
  - name: sigil
    repository:
      owner: sigil-dev
      name: homebrew-tap
    homepage: "https://github.com/sigil-dev/sigil"
    description: "Secure, lightweight Go gateway connecting messaging platforms to AI agents"
    license: "Apache-2.0"
    install: |
      bin.install "sigil"

dockers:
  - image_templates:
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-amd64"
    use: buildx
    build_flag_templates:
      - "--platform=linux/amd64"
    goarch: amd64
  - image_templates:
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-arm64"
    use: buildx
    build_flag_templates:
      - "--platform=linux/arm64"
    goarch: arm64

docker_manifests:
  - name_template: "ghcr.io/sigil-dev/sigil:{{ .Version }}"
    image_templates:
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-amd64"
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-arm64"
  - name_template: "ghcr.io/sigil-dev/sigil:latest"
    image_templates:
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-amd64"
      - "ghcr.io/sigil-dev/sigil:{{ .Version }}-arm64"
```

**Step 2: Validate**

```bash
task release:check
```

Expected: GoReleaser config validates with no errors.

**Step 3: Test snapshot build**

```bash
task release:snapshot
```

Expected: Local snapshot build completes.

**Step 4: Commit**

```bash
git add .goreleaser.yaml
git commit -m "build: add GoReleaser config with CGo, Cosign signing, dual SBOM, Homebrew, Docker"
```

---

## Task 6: Documentation Site

**Files:**

- Create: `site/zensical.toml`
- Create: `site/pyproject.toml`
- Create: `site/docs/getting-started/index.md`
- Create: `site/docs/guides/index.md`
- Create: `site/docs/plugins/index.md`
- Create: `site/docs/security/index.md`
- Create: `site/docs/reference/index.md`

**Step 1: Set up Zensical**

`site/pyproject.toml`:

```toml
[project]
name = "sigil-docs"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["zensical"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`site/zensical.toml`:

```toml
[site]
title = "Sigil Documentation"
description = "Secure, lightweight Go gateway for AI agents"
base_url = "https://docs.sigil.dev"

[nav]
auto = true

[theme]
primary_color = "#4f46e5"
```

**Step 2: Create initial documentation structure**

- `getting-started/index.md` — Installation, first-run, quickstart
- `guides/index.md` — Channel setup, workspace configuration, skill creation
- `plugins/index.md` — Plugin development guide, manifest reference, execution tiers
- `security/index.md` — Security model, capability reference, isolation tiers
- `reference/index.md` — CLI reference, config reference, API reference

Each page needs only a skeleton with headings and brief descriptions. Full content is a separate writing task.

**Step 3: Verify build**

```bash
cd site && uv sync && uv run zensical build
```

Expected: Site builds successfully.

**Step 4: Commit**

```bash
git add site/
git commit -m "docs: initialize documentation site with Zensical"
```

---

## Gate 7 Checklist

After completing all 6 tasks, verify:

- [ ] `task test` — all tests pass (including Phase 1–6 tests)
- [ ] `task lint` — zero lint errors
- [ ] SvelteKit UI builds without errors (`cd ui && npm run build`)
- [ ] TypeScript client generated from OpenAPI spec
- [ ] Chat page renders and sends messages (manual test against running gateway)
- [ ] Workspace, plugin, and settings pages render
- [ ] Tauri app builds in debug mode
- [ ] GoReleaser config validates (`task release:check`)
- [ ] Snapshot build completes (`task release:snapshot`)
- [ ] Doc site builds (`cd site && uv run zensical build`)
- [ ] Pre-release checklist items from `docs/decisions/pre-release-checklist.md` reviewed

---

## Post-Phase 7: Pre-Release

After all 7 phases complete, review `docs/decisions/pre-release-checklist.md` and address all items before any public release. This includes:

- OpenClaw attribution in NOTICE file
- License headers on all files
- Security audit of capability enforcement
- Integration testing with real LLM providers
- End-to-end test: message → channel → workspace → agent → provider → response → channel

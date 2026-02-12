# Section 10: Build and Distribution

## Toolchain

| Tool               | Purpose                                       | Notes                        |
| ------------------ | --------------------------------------------- | ---------------------------- |
| **Taskfile.dev**   | Build orchestration                           | All build/test/lint commands |
| **GoReleaser**     | Cross-compile, SBOM, Docker, GitHub releases  | CGo-enabled builds           |
| **Release-please** | Automated versioning, changelog, release PRs  | Handles semver               |
| **Cocogitto**      | Conventional commit validation only           | Does NOT handle versioning   |
| **Lefthook**       | Git hooks (lint, format, license, commit-msg) | Parallel pre-commit          |
| **Cosign**         | Keyless signing + attestation (GitHub OIDC)   | Signs checksums + Docker     |
| **Syft**           | SBOM generation (CycloneDX + SPDX)            | Dual format                  |
| **Zensical**       | Documentation site                            | uv-managed                   |
| **rumdl**          | Markdown linting                              | Rust binary, no Node.js      |
| **dprint**         | Code formatting (non-markdown)                | TOML, JSON, etc.             |
| **golangci-lint**  | Go linting                                    | Standard                     |
| **gofumpt**        | Go formatting                                 | Stricter than gofmt          |
| **yamlfmt**        | YAML formatting + linting                     |                              |
| **actionlint**     | GitHub Actions linting                        |                              |
| **addlicense**     | SPDX license header management                | Auto-added on commit         |
| **buf**            | Protobuf toolchain                            | Lint + generate              |

## Repository Structure

```text
project-root/
+-- Taskfile.yaml
+-- go.mod / go.sum
+-- buf.yaml / buf.gen.yaml
+-- cog.toml
+-- lefthook.yaml
+-- .goreleaser.yaml
+-- sigil.yaml.example
+-- LICENSE / LICENSE_HEADER
+--
+-- cmd/
|   +-- sigil/main.go                # main binary
|   +-- openapi-gen/main.go          # OpenAPI spec generator
|
+-- api/
|   +-- proto/                       # protobuf definitions
|   |   +-- sigil/v1/
|   |   +-- plugin/v1/
|   |   +-- common/v1/
|   +-- openapi/
|       +-- spec.yaml                # generated
|
+-- internal/                        # private Go packages
|   +-- server/                      # HTTP server, SSE, routing
|   +-- agent/                       # agent loop, sessions
|   +-- plugin/                      # plugin manager, host, lifecycle
|   |   +-- sandbox/                 # srt-style (bwrap/seatbelt)
|   |   +-- goplugin/                # go-plugin host
|   |   +-- wasm/                    # wazero host
|   +-- provider/                    # built-in LLM providers
|   |   +-- anthropic/
|   |   +-- openai/
|   |   +-- google/
|   +-- security/                    # enforcer, capabilities, audit
|   +-- memory/                      # tiered memory store
|   +-- config/                      # viper config management
|   +-- identity/                    # user identity, pairing
|   +-- workspace/                   # workspace management
|   +-- node/                        # node registration, routing
|   +-- gen/                         # generated code
|
+-- pkg/                             # public Go packages (plugin SDKs)
|   +-- plugin/
|       +-- sdk.go
|       +-- channel.go
|       +-- tool.go
|       +-- provider.go
|
+-- plugins/                         # first-party plugins (separate go modules)
|   +-- telegram-channel/
|   +-- discord-channel/
|   +-- whatsapp-channel/
|   +-- slack-channel/
|   +-- exec-sandbox/
|   +-- k8s-tools/
|
+-- ui/                              # SvelteKit + Tauri
|   +-- src/
|   |   +-- lib/api/generated/       # OpenAPI client
|   |   +-- routes/
|   +-- src-tauri/                   # Tauri config + sidecar
|   +-- package.json
|   +-- svelte.config.js
|
+-- skills/                          # bundled skills (agentskills.io)
|   +-- general-assistant/SKILL.md
|   +-- code-review/SKILL.md
|
+-- site/                            # doc site (zensical)
|   +-- docs/
|   |   +-- getting-started/
|   |   +-- guides/
|   |   +-- plugins/
|   |   +-- security/
|   |   +-- reference/
|   |   +-- operators/
|   +-- zensical.toml
|   +-- pyproject.toml
|
+-- docs/                            # internal docs
|   +-- design/                      # this design document
|   +-- decisions/                   # decision log
|   +-- plans/                       # implementation plans
|
+-- .github/
    +-- workflows/
        +-- ci.yaml
        +-- release.yaml
```

## CGo Cross-Compilation

Since CGo is required (sqlite3, sqlite-vec), cross-compilation needs C cross-compilers. Use `goreleaser-cross` Docker image in CI which bundles cross-compilers for all target platforms.

## Lefthook Configuration

```yaml
no_auto_install: true

pre-commit:
  parallel: true
  commands:
    license-headers:
      glob: "*.{go,lua,sh,py,proto}"
      exclude: "*.pb.go"
      run: |
        set -euo pipefail
        command -v addlicense >/dev/null 2>&1 || go install github.com/google/addlicense@latest
        addlicense -f LICENSE_HEADER {staged_files}
      stage_fixed: true
    lint-go:
      glob: "*.go"
      run: golangci-lint run --new-from-rev=HEAD~1
      stage_fixed: true
    lint-markdown:
      glob: "*.md"
      run: rumdl {staged_files}
    lint-yaml:
      glob: "*.{yaml,yml}"
      run: yamlfmt -lint {staged_files}
    lint-actions:
      glob: ".github/workflows/*.{yaml,yml}"
      run: actionlint {staged_files}
    format-check:
      run: dprint check
    api-sync:
      glob: "{api/proto/**/*.proto,internal/api/**/*.go}"
      run: |
        task generate
        git diff --exit-code api/openapi/spec.yaml internal/gen/ || {
          echo "API out of sync. Run 'task generate'."
          exit 1
        }
      stage_fixed: true
    ui-check:
      glob: "ui/src/**/*.{ts,svelte}"
      run: cd ui && npm run check

commit-msg:
  commands:
    conventional-commit:
      run: cog verify --file {1}
```

## GoReleaser Configuration

Key differences from holomush:

- `CGO_ENABLED=1` for sigil binary (sqlite3/sqlite-vec)
- `CGO_ENABLED=0` for plugin binaries (no C deps)
- Plugin binaries built alongside core
- Homebrew tap for easy installation
- Same SBOM (Syft dual-format) and Cosign signing as holomush

## Distribution Channels

| Channel             | Method                                 | Target                  |
| ------------------- | -------------------------------------- | ----------------------- |
| **Homebrew**        | `brew install sigil`                   | macOS/Linux power users |
| **curl installer**  | `curl -fsSL install.example.com \| sh` | Quick setup             |
| **Go install**      | `go install ...@latest`                | Go developers           |
| **Docker**          | `docker run sigil`                     | Container users         |
| **Tauri app**       | `.dmg` / `.msi` / `.AppImage`          | Desktop users           |
| **GitHub Releases** | Pre-built binaries                     | Everyone                |

## Key Dependency Choices

| Purpose   | Library                                   | Rationale                          |
| --------- | ----------------------------------------- | ---------------------------------- |
| CLI       | cobra + viper                             | Industry standard, config watching |
| HTTP/API  | huma (on chi)                             | OpenAPI 3.1 from Go types          |
| Proto     | buf                                       | Best proto tooling                 |
| Plugins   | hashicorp/go-plugin                       | Proven, gRPC-based                 |
| Wasm      | tetratelabs/wazero                        | Pure Go, no CGo, fast              |
| Sandbox   | Custom (srt-inspired)                     | OS-native: bwrap + seatbelt        |
| Database  | mattn/go-sqlite3                          | CGo required anyway                |
| Vector    | asg017/sqlite-vec                         | SQLite extension                   |
| FTS       | SQLite FTS5                               | Built-in                           |
| Tailscale | tailscale.com/tsnet                       | Embedded Tailscale node            |
| LLM SDKs  | anthropic-sdk-go, openai-go, Google genai | Official SDKs                      |
| Logging   | log/slog                                  | stdlib, structured                 |
| Errors    | samber/oops                               | Structured error context           |
| Testing   | stdlib + testify                          | Keep it simple                     |

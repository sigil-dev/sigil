# Sigil Tauri Desktop App

This directory contains the Tauri v2 desktop application wrapper for Sigil.

## Features

- **System Tray**: Always-accessible tray icon with quick actions
- **Sidecar Process**: Automatically manages the Sigil gateway binary
- **Auto-updates**: Built-in updater support via Tauri
- **Cross-platform**: macOS, Linux, Windows support

## Architecture

The Tauri app wraps the SvelteKit UI and manages a sidecar process running the Sigil gateway binary:

```text
┌─────────────────────────────────────┐
│  Tauri Desktop App (Rust)           │
│  ┌──────────────────────────────┐   │
│  │  SvelteKit UI (WebView)      │   │
│  │  - Chat interface            │   │
│  │  - Workspace management      │   │
│  │  - Settings                  │   │
│  └──────────────────────────────┘   │
│                                      │
│  System Tray Menu:                  │
│  - Open Sigil                       │
│  - Pause Agent                      │
│  - Restart Gateway                  │
│  - Quit                             │
│                                      │
│  Manages Sidecar:                   │
│  └─> sigil start --config ...       │
└─────────────────────────────────────┘
```

## Development

### Prerequisites

- Rust toolchain (1.70+)
- Node.js (for SvelteKit UI)
- Platform-specific dependencies:
  - **macOS**: Xcode Command Line Tools
  - **Linux**: webkit2gtk, libappindicator, etc.
  - **Windows**: WebView2

### Running in Dev Mode

```bash
cd ui
npm install
npm run tauri dev
```

This will:

1. Start the SvelteKit dev server (Vite)
2. Build and run the Tauri app
3. Auto-reload on code changes

### Building for Production

```bash
cd ui
npm run tauri build
```

Outputs to `ui/src-tauri/target/release/bundle/`

## Configuration

See `tauri.conf.json` for:

- Window settings
- Sidecar binary configuration
- Bundle settings (icons, identifier, etc.)
- Plugin configuration (shell, updater)

## Sidecar Binary

The Tauri app expects the Sigil gateway binary at:

- **Development**: `binaries/sigil` (relative to project root)
- **Production**: Bundled in `externalBin` during build

The sidecar is started with:

```bash
sigil start --config $APPDATA/sigil/sigil.yaml
```

## Icons

Replace `icons/icon.png` with a proper application icon before release. Current icon is a 1x1 placeholder.

Recommended icon sizes for all platforms:

- 32x32, 128x128, 256x256, 512x512 (PNG)
- For macOS: .icns file
- For Windows: .ico file

Use `tauri icon` command to generate all required sizes from a source PNG.

## System Tray Behavior

- **Left click**: Show/focus main window
- **Right click**: Show menu
- **Close window**: Hides window instead of quitting (app stays in tray)
- **Quit from tray**: Stops sidecar and exits app

## Security

- Sidecar binary is scoped via shell plugin configuration
- Only allowed args: `start`, `--config`, `<path>`
- CSP is set to null for SvelteKit compatibility (review for production)
- Asset protocol scoped to `$APPDATA/sigil/**`

## Auto-Updates

Configured in `tauri.conf.json` under `plugins.updater`:

- Endpoint: `https://releases.sigil.dev/{{target}}/{{arch}}/{{current_version}}`
- Requires signing key for production releases
- Set `pubkey` before enabling in production

## License

Apache-2.0 (see SPDX headers in source files)

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

/// <reference types="svelte" />
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

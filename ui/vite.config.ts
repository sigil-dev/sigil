// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 5173,
    strictPort: false,
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});

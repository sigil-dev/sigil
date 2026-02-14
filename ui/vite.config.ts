// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		port: 5173,
		strictPort: false
	}
});

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';

	let { children } = $props();

	// Sidecar error banner state
	let sidecarError = $state<string | null>(null);
	let sidecarReady = $state(false);

	onMount(() => {
		// Only set up Tauri listeners in desktop environment
		if (typeof window === 'undefined' || !('__TAURI__' in window)) return;

		let cleanup: (() => void) | undefined;

		(async () => {
			try {
				const { listen } = await import('@tauri-apps/api/event');

				// Listen for sidecar startup errors
				const errorUnlisten = await listen('sidecar-error', (event: any) => {
					console.error('Sidecar error:', event.payload);
					sidecarError = typeof event.payload === 'string'
						? event.payload
						: 'Sigil gateway failed to start. Please check the logs.';
				});

				// Listen for sidecar ready event
				const readyUnlisten = await listen('sidecar-ready', () => {
					console.log('Sidecar ready');
					sidecarReady = true;
					sidecarError = null;
				});

				// Store cleanup function to be called on unmount
				cleanup = () => {
					errorUnlisten();
					readyUnlisten();
				};
			} catch (e) {
				// Not in Tauri environment - ignore
				console.debug('Tauri API not available:', e);
			}
		})();

		// Return sync cleanup function
		return () => {
			cleanup?.();
		};
	});
</script>

{#if sidecarError}
	<div class="error-banner">
		<div class="error-content">
			<strong>Gateway Error:</strong>
			{sidecarError}
		</div>
		<button class="error-dismiss" onclick={() => (sidecarError = null)}>×</button>
	</div>
{/if}

{@render children()}

<style>
	.error-banner {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		background-color: #dc2626;
		color: white;
		padding: 1rem;
		display: flex;
		align-items: center;
		justify-content: space-between;
		z-index: 9999;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
	}

	.error-content {
		flex: 1;
		font-size: 0.875rem;
	}

	.error-content strong {
		font-weight: 600;
		margin-right: 0.5rem;
	}

	.error-dismiss {
		background: none;
		border: none;
		color: white;
		font-size: 1.5rem;
		cursor: pointer;
		padding: 0 0.5rem;
		line-height: 1;
		opacity: 0.8;
	}

	.error-dismiss:hover {
		opacity: 1;
	}
</style>

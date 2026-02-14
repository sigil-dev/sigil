<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';

	let { children } = $props();

	// Sidecar error banner state
	let sidecarError = $state<string | null>(null);
	let sidecarReady = $state(false);
	let sidecarStatus = $state<string | null>(null);

	onMount(() => {
		// Only set up Tauri listeners in desktop environment
		if (typeof window === 'undefined' || !('__TAURI__' in window)) return;

		let cleanup: (() => void) | undefined;

		(async () => {
			try {
				const { listen } = await import('@tauri-apps/api/event');

				// Listen for sidecar startup errors
				const errorUnlisten = await listen<string>('sidecar-error', (event) => {
					console.error('Sidecar error:', event.payload);
					sidecarError = typeof event.payload === 'string'
						? event.payload
						: 'Sigil gateway failed to start. Please check the logs.';
					sidecarStatus = null;
				});

				// Listen for sidecar ready event
				const readyUnlisten = await listen('sidecar-ready', () => {
					console.log('Sidecar ready');
					sidecarReady = true;
					sidecarError = null;
					sidecarStatus = null;
				});

				// Listen for sidecar checking events
				const checkingUnlisten = await listen<string>('sidecar-checking', (event) => {
					sidecarStatus = event.payload;
				});

				// Listen for sidecar retry events
				const retryUnlisten = await listen<string>('sidecar-retry', (event) => {
					sidecarStatus = event.payload;
				});

				// Store cleanup function to be called on unmount
				cleanup = () => {
					errorUnlisten();
					readyUnlisten();
					checkingUnlisten();
					retryUnlisten();
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
{:else if sidecarStatus}
	<div class="status-banner">
		<div class="status-content">
			{sidecarStatus}
		</div>
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

	.status-banner {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		background-color: #3b82f6;
		color: white;
		padding: 0.5rem 1rem;
		display: flex;
		align-items: center;
		z-index: 9999;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
	}

	.status-content {
		flex: 1;
		font-size: 0.875rem;
		text-align: center;
	}
</style>

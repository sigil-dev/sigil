<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import type { components } from '$lib/api/generated/schema';

	type PluginSummary = components['schemas']['PluginSummary'];
	type PluginDetail = components['schemas']['PluginDetail'];

	let plugins = $state<PluginSummary[]>([]);
	let selectedPlugin = $state<PluginDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let reloading = $state<string | null>(null);

	onMount(async () => {
		await loadPlugins();
	});

	async function loadPlugins() {
		loading = true;
		error = null;
		try {
			const { data, error: err } = await api.GET('/api/v1/plugins');
			if (err) {
				error = err.detail || 'Failed to load plugins';
			} else {
				plugins = data?.plugins || [];
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	}

	async function viewDetails(name: string) {
		try {
			const { data, error: err } = await api.GET('/api/v1/plugins/{name}', {
				params: { path: { name } }
			});
			if (err) {
				error = err.detail || 'Failed to load plugin details';
			} else {
				selectedPlugin = data;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		}
	}

	async function reloadPlugin(name: string) {
		reloading = name;
		try {
			const { error: err } = await api.POST('/api/v1/plugins/{name}/reload', {
				params: { path: { name } }
			});
			if (err) {
				error = err.detail || 'Failed to reload plugin';
			} else {
				await loadPlugins();
				if (selectedPlugin?.name === name) {
					selectedPlugin = null;
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			reloading = null;
		}
	}

	function closeDetails() {
		selectedPlugin = null;
	}

	function getTierBadgeClass(tier: string): string {
		switch (tier) {
			case 'wasm':
				return 'tier-wasm';
			case 'process':
				return 'tier-process';
			case 'container':
				return 'tier-container';
			default:
				return '';
		}
	}

	function getStatusBadgeClass(status: string): string {
		switch (status) {
			case 'running':
				return 'status-running';
			case 'stopped':
				return 'status-stopped';
			case 'error':
				return 'status-error';
			default:
				return '';
		}
	}

	function viewLogs(name: string) {
		console.log('View logs for:', name);
		alert('Plugin logs coming soon');
	}

	function removePlugin(name: string) {
		console.log('Remove plugin:', name);
		if (confirm(`Remove plugin "${name}"?`)) {
			alert('Plugin removal coming soon');
		}
	}

	function inspectManifest(name: string) {
		console.log('Inspect manifest for:', name);
		alert('Manifest inspection coming soon');
	}
</script>

<div class="container">
	<header>
		<div class="header-row">
			<div>
				<h1>Plugins</h1>
				<p>Manage installed plugins and view execution status</p>
			</div>
			<button class="install-btn" disabled title="Plugin installation coming soon">
				Install Plugin
			</button>
		</div>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	{#if loading}
		<div class="loading">Loading plugins...</div>
	{:else if plugins.length === 0}
		<div class="empty">No plugins installed</div>
	{:else}
		<table>
			<thead>
				<tr>
					<th>Name</th>
					<th>Type</th>
					<th>Version</th>
					<th>Status</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each plugins as plugin}
					<tr>
						<td><code>{plugin.name}</code></td>
						<td><span class="type-badge">{plugin.type}</span></td>
						<td>{plugin.version}</td>
						<td>
							<span class="status-badge {getStatusBadgeClass(plugin.status)}">
								{plugin.status}
							</span>
						</td>
						<td class="actions-cell">
							<button onclick={() => viewDetails(plugin.name)} disabled={reloading !== null}>
								Details
							</button>
							<button
								onclick={() => reloadPlugin(plugin.name)}
								disabled={reloading !== null}
							>
								{reloading === plugin.name ? 'Reloading...' : 'Reload'}
							</button>
							<button onclick={() => viewLogs(plugin.name)} disabled={reloading !== null}>
								Logs
							</button>
							<button onclick={() => inspectManifest(plugin.name)} disabled={reloading !== null}>
								Manifest
							</button>
							<button onclick={() => removePlugin(plugin.name)} disabled={reloading !== null} class="remove-action">
								Remove
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</div>

{#if selectedPlugin}
	<div class="modal-overlay" onclick={closeDetails} role="presentation" onkeydown={(e) => e.key === 'Escape' && closeDetails()}>
		<div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Plugin details" tabindex="-1">
			<header>
				<h2>{selectedPlugin.name}</h2>
				<button class="close-btn" onclick={closeDetails}>&times;</button>
			</header>

			<div class="modal-content">
				<section>
					<h3>Plugin Information</h3>
					<dl>
						<dt>Type</dt>
						<dd><span class="type-badge">{selectedPlugin.type}</span></dd>
						<dt>Version</dt>
						<dd>{selectedPlugin.version}</dd>
						<dt>Status</dt>
						<dd>
							<span class="status-badge {getStatusBadgeClass(selectedPlugin.status)}">
								{selectedPlugin.status}
							</span>
						</dd>
						<dt>Execution Tier</dt>
						<dd>
							<span class="tier-badge {getTierBadgeClass(selectedPlugin.tier)}">
								{selectedPlugin.tier}
							</span>
						</dd>
					</dl>
				</section>

				<section>
					<h3>Granted Capabilities</h3>
					{#if selectedPlugin.capabilities && selectedPlugin.capabilities.length > 0}
						<ul class="capabilities">
							{#each selectedPlugin.capabilities as capability}
								<li><code>{capability}</code></li>
							{/each}
						</ul>
					{:else}
						<p class="empty-state">No capabilities granted</p>
					{/if}
				</section>
			</div>
		</div>
	</div>
{/if}

<style>
	.container {
		max-width: 1200px;
		margin: 0 auto;
		padding: 2rem;
	}

	header {
		margin-bottom: 2rem;
	}

	h1 {
		font-size: 2rem;
		margin-bottom: 0.5rem;
	}

	header p {
		color: #666;
		font-size: 0.95rem;
	}

	.header-row {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
	}

	.install-btn {
		padding: 0.6rem 1.2rem;
		background: #4a90d9;
		color: white;
		border: none;
		border-radius: 6px;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: not-allowed;
		opacity: 0.5;
		white-space: nowrap;
	}

	.resource-placeholder {
		color: #aaa;
		font-size: 0.85rem;
	}

	.loading,
	.error,
	.empty {
		padding: 2rem;
		text-align: center;
		border-radius: 8px;
		background: #f5f5f5;
	}

	.error {
		background: #fee;
		color: #c00;
		margin-bottom: 1rem;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		background: white;
		border: 1px solid #ddd;
		border-radius: 8px;
		overflow: hidden;
	}

	th {
		text-align: left;
		padding: 1rem;
		background: #f5f5f5;
		border-bottom: 2px solid #ddd;
		font-weight: 600;
		color: #666;
	}

	td {
		padding: 1rem;
		border-bottom: 1px solid #eee;
	}

	tr:last-child td {
		border-bottom: none;
	}

	code {
		font-family: monospace;
		background: #f5f5f5;
		padding: 0.2rem 0.4rem;
		border-radius: 3px;
		font-size: 0.9rem;
	}

	.type-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		background: #e3f2fd;
		color: #1976d2;
	}

	.status-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 600;
	}

	.status-badge.status-running {
		background: #e8f5e9;
		color: #2e7d32;
	}

	.status-badge.status-stopped {
		background: #f5f5f5;
		color: #757575;
	}

	.status-badge.status-error {
		background: #ffebee;
		color: #c62828;
	}

	.tier-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 600;
	}

	.tier-badge.tier-wasm {
		background: #fff3e0;
		color: #e65100;
	}

	.tier-badge.tier-process {
		background: #e8eaf6;
		color: #3f51b5;
	}

	.tier-badge.tier-container {
		background: #fce4ec;
		color: #c2185b;
	}

	button {
		padding: 0.5rem 1rem;
		border: 1px solid #ddd;
		border-radius: 4px;
		background: white;
		color: #0066cc;
		cursor: pointer;
		font-size: 0.9rem;
		margin-right: 0.5rem;
	}

	button:hover:not(:disabled) {
		background: #f5f5f5;
		border-color: #0066cc;
	}

	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.actions-cell {
		white-space: nowrap;
	}

	.actions-cell button {
		margin-right: 0.25rem;
		margin-bottom: 0.25rem;
	}

	.remove-action {
		color: #c00;
	}

	.remove-action:hover:not(:disabled) {
		border-color: #c00;
		background: #fee;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal {
		background: white;
		border-radius: 8px;
		width: 90%;
		max-width: 600px;
		max-height: 80vh;
		overflow: auto;
	}

	.modal header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.5rem;
		border-bottom: 1px solid #ddd;
	}

	.modal h2 {
		margin: 0;
		font-size: 1.5rem;
	}

	.close-btn {
		background: none;
		border: none;
		font-size: 2rem;
		color: #999;
		cursor: pointer;
		padding: 0;
		margin: 0;
		width: 2rem;
		height: 2rem;
		line-height: 1;
	}

	.close-btn:hover {
		color: #333;
	}

	.modal-content {
		padding: 1.5rem;
	}

	.modal-content section {
		margin-bottom: 2rem;
	}

	.modal-content section:last-child {
		margin-bottom: 0;
	}

	.modal-content h3 {
		font-size: 1.1rem;
		margin-bottom: 1rem;
		color: #333;
	}

	dl {
		display: grid;
		grid-template-columns: 150px 1fr;
		gap: 0.75rem;
	}

	dt {
		font-weight: 600;
		color: #666;
	}

	dd {
		margin: 0;
		color: #333;
	}

	.capabilities {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.capabilities li {
		padding: 0.5rem 0;
		border-bottom: 1px solid #eee;
	}

	.capabilities li:last-child {
		border-bottom: none;
	}

	.empty-state {
		color: #999;
		text-align: center;
		padding: 1rem;
	}
</style>

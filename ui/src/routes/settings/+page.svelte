<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import type { components } from '$lib/api/generated/schema';

	type UserSummary = components['schemas']['UserSummary'];

	let users = $state<UserSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let activeTab = $state<'providers' | 'global' | 'users' | 'audit'>('providers');

	onMount(async () => {
		await loadUsers();
	});

	async function loadUsers() {
		try {
			const { data, error: err } = await api.GET('/api/v1/users');
			if (err) {
				error = err.detail || 'Failed to load users';
			} else {
				users = data?.users || [];
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	}

	// Placeholder data for settings not yet in API
	const providers = [
		{ name: 'anthropic', status: 'configured', model: 'claude-opus-4.6' },
		{ name: 'openai', status: 'not-configured', model: '' },
		{ name: 'google', status: 'configured', model: 'gemini-2.0-flash' }
	];

	const globalSettings = {
		networkingMode: 'local',
		defaultModel: 'claude-opus-4.6',
		dailyBudget: 100.0,
		monthlyBudget: 3000.0
	};

	const auditLogs = [
		{ timestamp: '2026-02-13T10:30:00Z', user: 'alice', action: 'workspace.create', target: 'personal' },
		{ timestamp: '2026-02-13T09:15:00Z', user: 'bob', action: 'plugin.reload', target: 'anthropic' },
		{ timestamp: '2026-02-13T08:45:00Z', user: 'alice', action: 'session.start', target: 'sess-123' },
		{ timestamp: '2026-02-13T08:30:00Z', user: 'charlie', action: 'workspace.delete', target: 'test' },
		{ timestamp: '2026-02-13T08:00:00Z', user: 'alice', action: 'plugin.install', target: 'google' },
		{ timestamp: '2026-02-13T07:45:00Z', user: 'bob', action: 'session.end', target: 'sess-122' }
	];

	let auditFilterText = $state('');
	let auditFilterAction = $state('all');

	const filteredAuditLogs = $derived.by(() => {
		let filtered = auditLogs;

		// Filter by text (user or action)
		if (auditFilterText.trim()) {
			const searchLower = auditFilterText.toLowerCase();
			filtered = filtered.filter(
				(log) =>
					log.user.toLowerCase().includes(searchLower) ||
					log.action.toLowerCase().includes(searchLower)
			);
		}

		// Filter by action type
		if (auditFilterAction !== 'all') {
			filtered = filtered.filter((log) => log.action.startsWith(auditFilterAction));
		}

		return filtered;
	});

	function setTab(tab: typeof activeTab) {
		activeTab = tab;
	}
</script>

<div class="container">
	<header>
		<h1>Settings</h1>
		<p>Configure gateway, providers, and security settings</p>
	</header>

	{#if error}
		<div class="error">{error}</div>
	{/if}

	<nav class="tabs">
		<button class:active={activeTab === 'providers'} onclick={() => setTab('providers')}>
			Providers
		</button>
		<button class:active={activeTab === 'global'} onclick={() => setTab('global')}>
			Global Settings
		</button>
		<button class:active={activeTab === 'users'} onclick={() => setTab('users')}>
			Users
		</button>
		<button class:active={activeTab === 'audit'} onclick={() => setTab('audit')}>
			Audit Log
		</button>
	</nav>

	<div class="content">
		{#if activeTab === 'providers'}
			<section class="panel">
				<h2>Provider Configuration</h2>
				<p class="panel-description">
					Configure LLM providers with API keys and default models. Settings will be saved to sigil.yaml.
				</p>

				<div class="preview-banner">Preview — not connected to live data</div>

				<div class="provider-list">
					{#each providers as provider}
						<div class="provider-card">
							<div class="provider-header">
								<h3>{provider.name}</h3>
								<span class="status-badge {provider.status === 'configured' ? 'configured' : 'not-configured'}">
									{provider.status}
								</span>
							</div>
							{#if provider.status === 'configured'}
								<div class="provider-details">
									<label>
										<span>Default Model</span>
										<input type="text" value={provider.model} readonly />
									</label>
									<label>
										<span>API Key</span>
										<input type="password" value="sk-..." readonly />
									</label>
								</div>
							{:else}
								<p class="empty-state">Not configured. Add API key to sigil.yaml to enable.</p>
							{/if}
						</div>
					{/each}
				</div>
			</section>
		{:else if activeTab === 'global'}
			<section class="panel">
				<h2>Global Settings</h2>
				<p class="panel-description">
					Gateway-wide configuration affecting all workspaces and sessions.
				</p>

				<form class="settings-form">
					<label>
						<span>Networking Mode</span>
						<select value={globalSettings.networkingMode}>
							<option value="local">Local only</option>
							<option value="tailscale">Tailscale (tsnet)</option>
						</select>
					</label>

					<label>
						<span>Default Model</span>
						<input type="text" value={globalSettings.defaultModel} />
					</label>

					<label>
						<span>Daily Budget (USD)</span>
						<input type="number" value={globalSettings.dailyBudget} step="0.01" />
					</label>

					<label>
						<span>Monthly Budget (USD)</span>
						<input type="number" value={globalSettings.monthlyBudget} step="0.01" />
					</label>

					<div class="form-actions">
						<button type="button" disabled>Save Settings (not yet implemented)</button>
					</div>
				</form>
			</section>
		{:else if activeTab === 'users'}
			<section class="panel">
				<h2>User Management</h2>
				<p class="panel-description">
					Manage users and pairing for channel access.
				</p>

				{#if loading}
					<div class="loading">Loading users...</div>
				{:else if users.length === 0}
					<div class="empty">No users found</div>
				{:else}
					<table>
						<thead>
							<tr>
								<th>ID</th>
								<th>Name</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{#each users as user}
								<tr>
									<td><code>{user.id}</code></td>
									<td>{user.name}</td>
									<td>
										<button disabled>Edit</button>
										<button disabled>Unpair</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</section>
		{:else if activeTab === 'audit'}
			<section class="panel">
				<h2>Audit Log</h2>
				<p class="panel-description">
					Security-relevant operations and administrative actions.
				</p>

				<div class="preview-banner">Preview — showing sample data</div>

				<div class="audit-filters">
					<input
						type="text"
						placeholder="Filter by user or action..."
						bind:value={auditFilterText}
					/>
					<select bind:value={auditFilterAction}>
						<option value="all">All actions</option>
						<option value="workspace">workspace.*</option>
						<option value="plugin">plugin.*</option>
						<option value="session">session.*</option>
					</select>
				</div>

				<table>
					<thead>
						<tr>
							<th>Timestamp</th>
							<th>User</th>
							<th>Action</th>
							<th>Target</th>
						</tr>
					</thead>
					<tbody>
						{#each filteredAuditLogs as log}
							<tr>
								<td>{new Date(log.timestamp).toLocaleString()}</td>
								<td><code>{log.user}</code></td>
								<td><span class="action-badge">{log.action}</span></td>
								<td><code>{log.target}</code></td>
							</tr>
						{/each}
					</tbody>
				</table>

				{#if filteredAuditLogs.length === 0}
					<p class="empty-state">No audit logs match the current filters</p>
				{/if}
			</section>
		{/if}
	</div>
</div>

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

	.error {
		padding: 1rem;
		background: #fee;
		color: #c00;
		border-radius: 8px;
		margin-bottom: 1rem;
	}

	.tabs {
		display: flex;
		gap: 0.5rem;
		border-bottom: 2px solid #ddd;
		margin-bottom: 2rem;
	}

	.tabs button {
		padding: 0.75rem 1.5rem;
		border: none;
		background: none;
		color: #666;
		cursor: pointer;
		font-size: 1rem;
		border-bottom: 2px solid transparent;
		margin-bottom: -2px;
		transition: all 0.2s;
	}

	.tabs button:hover {
		color: #0066cc;
	}

	.tabs button.active {
		color: #0066cc;
		border-bottom-color: #0066cc;
		font-weight: 600;
	}

	.panel {
		background: white;
		border: 1px solid #ddd;
		border-radius: 8px;
		padding: 2rem;
	}

	.panel h2 {
		font-size: 1.5rem;
		margin-bottom: 0.5rem;
	}

	.panel-description {
		color: #666;
		margin-bottom: 2rem;
	}

	.provider-list {
		display: grid;
		gap: 1.5rem;
	}

	.provider-card {
		border: 1px solid #ddd;
		border-radius: 8px;
		padding: 1.5rem;
	}

	.provider-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.provider-header h3 {
		font-size: 1.25rem;
		margin: 0;
		text-transform: capitalize;
	}

	.status-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 600;
	}

	.status-badge.configured {
		background: #e8f5e9;
		color: #2e7d32;
	}

	.status-badge.not-configured {
		background: #f5f5f5;
		color: #757575;
	}

	.provider-details {
		display: grid;
		gap: 1rem;
	}

	.settings-form {
		display: grid;
		gap: 1.5rem;
		max-width: 600px;
	}

	label {
		display: grid;
		gap: 0.5rem;
	}

	label span {
		font-weight: 600;
		color: #666;
	}

	input[type='text'],
	input[type='password'],
	input[type='number'],
	select {
		padding: 0.75rem;
		border: 1px solid #ddd;
		border-radius: 4px;
		font-size: 1rem;
	}

	input[readonly] {
		background: #f5f5f5;
		color: #999;
	}

	.form-actions {
		display: flex;
		gap: 1rem;
		margin-top: 1rem;
	}

	button {
		padding: 0.5rem 1rem;
		border: 1px solid #ddd;
		border-radius: 4px;
		background: white;
		color: #0066cc;
		cursor: pointer;
		font-size: 0.9rem;
	}

	button:hover {
		background: #f5f5f5;
		border-color: #0066cc;
	}

	.form-actions button {
		background: #0066cc;
		color: white;
		border-color: #0066cc;
	}

	.form-actions button:hover {
		background: #0052a3;
	}

	.loading,
	.empty {
		padding: 2rem;
		text-align: center;
		color: #999;
	}

	.empty-state {
		color: #999;
		text-align: center;
		padding: 1rem;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		margin-top: 1rem;
	}

	th {
		text-align: left;
		padding: 0.75rem;
		border-bottom: 2px solid #ddd;
		font-weight: 600;
		color: #666;
	}

	td {
		padding: 0.75rem;
		border-bottom: 1px solid #eee;
	}

	code {
		font-family: monospace;
		background: #f5f5f5;
		padding: 0.2rem 0.4rem;
		border-radius: 3px;
		font-size: 0.9rem;
	}

	.action-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
		background: #e3f2fd;
		color: #1976d2;
	}

	.audit-filters {
		display: flex;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.audit-filters input {
		flex: 1;
	}

	.audit-filters select {
		width: 200px;
	}

	.preview-banner {
		padding: 0.5rem 1rem;
		background: #fff3cd;
		color: #856404;
		border: 1px solid #ffc107;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 600;
		margin-bottom: 1rem;
		text-align: center;
	}

	button:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
</style>

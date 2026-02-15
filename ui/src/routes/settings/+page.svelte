<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import { classifyError } from '$lib/stores/classify-error';
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
			error = classifyError(e).message;
		} finally {
			loading = false;
		}
	}


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
				<p class="panel-description">Configure LLM providers with API keys and default models.</p>
				<div class="coming-soon">Coming soon — provider configuration API not yet available</div>
			</section>
		{:else if activeTab === 'global'}
			<section class="panel">
				<h2>Global Settings</h2>
				<p class="panel-description">Gateway-wide configuration affecting all workspaces and sessions.</p>
				<div class="coming-soon">Coming soon — settings API not yet available</div>
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
				<p class="panel-description">Security-relevant operations and administrative actions.</p>
				<div class="coming-soon">Coming soon — audit log API not yet available</div>
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

	.coming-soon {
		padding: 1.5rem;
		text-align: center;
		color: #856404;
		background: #fff3cd;
		border: 1px solid #ffc107;
		border-radius: 4px;
		font-size: 0.9rem;
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

	.loading,
	.empty {
		padding: 2rem;
		text-align: center;
		color: #999;
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

	button:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
</style>

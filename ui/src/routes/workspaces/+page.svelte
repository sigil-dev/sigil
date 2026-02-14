<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import type { components } from '$lib/api/generated/schema';

	type WorkspaceSummary = components['schemas']['WorkspaceSummary'];

	let workspaces = $state<WorkspaceSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			const { data, error: err } = await api.GET('/api/v1/workspaces');
			if (err) {
				error = err.detail || 'Failed to load workspaces';
			} else {
				workspaces = data?.workspaces || [];
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	});
</script>

<div class="container">
	<header>
		<h1>Workspaces</h1>
		<p>Manage workspace contexts for agent sessions</p>
	</header>

	{#if loading}
		<div class="loading">Loading workspaces...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if workspaces.length === 0}
		<div class="empty">No workspaces found</div>
	{:else}
		<div class="workspace-grid">
			{#each workspaces as workspace}
				<a href="/workspaces/{workspace.id}" class="workspace-card">
					<h2>{workspace.id}</h2>
					<p>{workspace.description}</p>
				</a>
			{/each}
		</div>
	{/if}
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
	}

	.workspace-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
		gap: 1.5rem;
	}

	.workspace-card {
		display: block;
		padding: 1.5rem;
		border: 1px solid #ddd;
		border-radius: 8px;
		text-decoration: none;
		color: inherit;
		transition: all 0.2s;
	}

	.workspace-card:hover {
		border-color: #0066cc;
		box-shadow: 0 2px 8px rgba(0, 102, 204, 0.1);
	}

	.workspace-card h2 {
		font-size: 1.25rem;
		margin-bottom: 0.5rem;
		color: #0066cc;
	}

	.workspace-card p {
		color: #666;
		font-size: 0.9rem;
		margin: 0;
	}
</style>

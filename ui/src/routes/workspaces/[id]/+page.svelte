<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { api } from '$lib/api/client';
	import { classifyError } from '$lib/stores/classify-error';
	import type { components } from '$lib/api/generated/schema';

	type WorkspaceDetail = components['schemas']['WorkspaceDetail'];
	type SessionSummary = components['schemas']['SessionSummary'];

	let workspace = $state<WorkspaceDetail | null>(null);
	let sessions = $state<SessionSummary[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	const workspaceId = $derived($page.params.id);

	onMount(async () => {
		if (!workspaceId) {
			error = 'No workspace ID provided';
			loading = false;
			return;
		}

		try {
			const [wsResp, sessResp] = await Promise.all([
				api.GET('/api/v1/workspaces/{id}', { params: { path: { id: workspaceId } } }),
				api.GET('/api/v1/workspaces/{id}/sessions', { params: { path: { id: workspaceId } } })
			]);

			if (wsResp.error) {
				error = wsResp.error.detail || 'Failed to load workspace';
			} else {
				workspace = wsResp.data;
			}

			if (sessResp.error) {
				error = sessResp.error.detail || 'Failed to load sessions';
			} else {
				sessions = sessResp.data?.sessions || [];
			}
		} catch (e) {
			error = classifyError(e).message;
		} finally {
			loading = false;
		}
	});

</script>

<div class="container">
	{#if loading}
		<div class="loading">Loading workspace...</div>
	{:else if error}
		<div class="error">{error}</div>
	{:else if workspace}
		<header>
			<h1>{workspace.id}</h1>
			<p>{workspace.description}</p>
		</header>

		<div class="grid">
			<section class="card">
				<h2>Configuration</h2>
				<dl>
					<dt>Default Model</dt>
					<dd>{workspace.model || 'None (use gateway default)'}</dd>
					<dt>Members</dt>
					<dd>{workspace.members?.length || 0} user(s)</dd>
					<dt>Budget</dt>
					<dd>Coming soon</dd>
				</dl>
			</section>

			<section class="card">
				<h2>Channels</h2>
				<div class="coming-soon">Coming soon — channel binding requires Phase 6 APIs</div>
			</section>

			<section class="card">
				<h2>Nodes</h2>
				<div class="coming-soon">Coming soon — node management requires Phase 6 APIs</div>
			</section>

			<section class="card">
				<h2>Allowed Tools</h2>
				<div class="coming-soon">Coming soon — tool allowlists require Phase 6 APIs</div>
			</section>

			<section class="card">
				<h2>Available Skills</h2>
				<div class="coming-soon">Coming soon — skill management requires Phase 6 APIs</div>
			</section>

			<section class="card full-width">
				<h2>Sessions</h2>
				{#if sessions.length === 0}
					<p class="empty-state">No sessions yet</p>
				{:else}
					<table>
						<thead>
							<tr>
								<th>ID</th>
								<th>Status</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{#each sessions as session}
								<tr>
									<td><code>{session.id}</code></td>
									<td><span class="status-badge {session.status}">{session.status}</span></td>
									<td>
										<a href="/workspaces/{workspaceId}/sessions/{session.id}">View</a>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</section>
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
	.error {
		padding: 2rem;
		text-align: center;
		border-radius: 8px;
		background: #f5f5f5;
	}

	.error {
		background: #fee;
		color: #c00;
	}

	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
		gap: 1.5rem;
	}

	.card {
		padding: 1.5rem;
		border: 1px solid #ddd;
		border-radius: 8px;
		background: white;
	}

	.card.full-width {
		grid-column: 1 / -1;
	}

	.card h2 {
		font-size: 1.25rem;
		margin-bottom: 1rem;
		color: #333;
	}

	dl {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 0.5rem;
	}

	dt {
		font-weight: 600;
		color: #666;
	}

	dd {
		margin: 0;
		color: #333;
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

	table {
		width: 100%;
		border-collapse: collapse;
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

	.status-badge {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		font-size: 0.85rem;
		font-weight: 600;
	}

	.status-badge.active {
		background: #e8f5e9;
		color: #2e7d32;
	}

	.status-badge.archived {
		background: #f5f5f5;
		color: #757575;
	}

	a {
		color: #0066cc;
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}
</style>

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { api } from '$lib/api/client';
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
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	});

	// Placeholder data for features not yet in API
	const placeholderChannels = ['telegram-main', 'discord-dev'];
	const placeholderNodes = ['laptop', 'desktop'];
	const placeholderTools = ['file-access', 'web-search', 'code-exec'];
	const placeholderSkills = ['summarize', 'translate', 'analyze-code'];

	function handleAddSkill() {
		console.log('Add skill - Coming soon');
		alert('Skill management coming soon');
	}

	function handleRemoveSkill(skill: string) {
		console.log('Remove skill:', skill);
		alert('Skill management coming soon');
	}

	function handleToggleTool(tool: string) {
		console.log('Toggle tool:', tool);
		alert('Tool allowlist configuration coming soon');
	}

	function handleBindChannel(channel: string) {
		console.log('Bind channel:', channel);
		alert('Channel binding coming soon');
	}

	function handleUnbindChannel(channel: string) {
		console.log('Unbind channel:', channel);
		alert('Channel unbinding coming soon');
	}

	function handleBindNode(node: string) {
		console.log('Bind node:', node);
		alert('Node binding coming soon');
	}

	function handleUnbindNode(node: string) {
		console.log('Unbind node:', node);
		alert('Node unbinding coming soon');
	}
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
				</dl>
			</section>

			<section class="card">
				<h2>Channels</h2>
				<div class="section-actions">
					<button onclick={() => handleBindChannel('')}>Bind Channel</button>
				</div>
				<ul>
					{#each placeholderChannels as channel}
						<li>
							<span class="badge">channel</span> {channel}
							<button class="remove-btn" onclick={() => handleUnbindChannel(channel)}>Unbind</button>
						</li>
					{/each}
				</ul>
			</section>

			<section class="card">
				<h2>Nodes</h2>
				<div class="section-actions">
					<button onclick={() => handleBindNode('')}>Bind Node</button>
				</div>
				<ul>
					{#each placeholderNodes as node}
						<li>
							<span class="badge">node</span> {node}
							<button class="remove-btn" onclick={() => handleUnbindNode(node)}>Unbind</button>
						</li>
					{/each}
				</ul>
			</section>

			<section class="card">
				<h2>Allowed Tools</h2>
				<p class="section-help">Toggle tools to control which capabilities are available to agents.</p>
				<ul class="tool-list">
					{#each placeholderTools as tool}
						<li>
							<label class="toggle-control">
								<input type="checkbox" checked onchange={() => handleToggleTool(tool)} />
								<span class="toggle-label">
									<span class="badge">tool</span> {tool}
								</span>
							</label>
						</li>
					{/each}
				</ul>
			</section>

			<section class="card">
				<h2>Available Skills</h2>
				<div class="section-actions">
					<button onclick={handleAddSkill}>Add Skill</button>
				</div>
				<ul>
					{#each placeholderSkills as skill}
						<li>
							<span class="badge">skill</span> {skill}
							<button class="remove-btn" onclick={() => handleRemoveSkill(skill)}>Remove</button>
						</li>
					{/each}
				</ul>
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

	ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	li {
		padding: 0.5rem 0;
		border-bottom: 1px solid #eee;
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	li:last-child {
		border-bottom: none;
	}

	.section-actions {
		margin-bottom: 1rem;
	}

	.section-actions button {
		padding: 0.5rem 1rem;
		border: 1px solid #0066cc;
		border-radius: 4px;
		background: white;
		color: #0066cc;
		cursor: pointer;
		font-size: 0.9rem;
	}

	.section-actions button:hover {
		background: #0066cc;
		color: white;
	}

	.remove-btn {
		padding: 0.25rem 0.5rem;
		border: 1px solid #ddd;
		border-radius: 4px;
		background: white;
		color: #c00;
		cursor: pointer;
		font-size: 0.85rem;
	}

	.remove-btn:hover {
		background: #fee;
		border-color: #c00;
	}

	.section-help {
		color: #666;
		font-size: 0.9rem;
		margin-bottom: 1rem;
	}

	.tool-list {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.toggle-control {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		width: 100%;
	}

	.toggle-control input[type='checkbox'] {
		cursor: pointer;
	}

	.toggle-label {
		flex: 1;
	}

	.badge {
		display: inline-block;
		padding: 0.2rem 0.5rem;
		font-size: 0.75rem;
		border-radius: 4px;
		background: #e0e0e0;
		color: #333;
		font-weight: 600;
		text-transform: uppercase;
	}

	.empty-state {
		color: #999;
		text-align: center;
		padding: 2rem;
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

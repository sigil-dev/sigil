<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { chatStore } from '$lib/stores/chat.svelte';
	import ChatMessage from '$lib/components/ChatMessage.svelte';
	import ChatInput from '$lib/components/ChatInput.svelte';
	import { onMount } from 'svelte';

	let messagesContainer: HTMLElement | undefined = $state();

	const hasWorkspace = $derived(chatStore.workspaceId !== null);
	const hasMessages = $derived(chatStore.messages.length > 0);

	onMount(() => {
		chatStore.loadSidebar();
	});

	$effect(() => {
		// Scroll to bottom when messages change
		if (chatStore.messages.length && messagesContainer) {
			messagesContainer.scrollTop = messagesContainer.scrollHeight;
		}
	});

	function handleSend(content: string): void {
		chatStore.sendMessage(content);
	}

	function handleCancel(): void {
		chatStore.cancel();
	}

	function selectSession(workspaceId: string, sessionId: string): void {
		chatStore.selectSession(workspaceId, sessionId);
	}

	function startNewSession(workspaceId: string): void {
		chatStore.newSession(workspaceId);
	}
</script>

<div class="chat-page">
	<aside class="chat-sidebar">
		<div class="chat-sidebar__header">
			<h2>Sessions</h2>
		</div>

		<div class="chat-sidebar__content">
			{#if chatStore.sidebarLoading}
				<div class="chat-sidebar__loading">Loading...</div>
			{:else if chatStore.workspaceGroups.length === 0}
				<div class="chat-sidebar__empty">
					No workspaces found. Create a workspace to start chatting.
				</div>
			{:else}
				{#each chatStore.workspaceGroups as group}
					<div class="workspace-group">
						<div class="workspace-group__header">
							<span class="workspace-group__name" title={group.id}>
								{group.description || group.id}
							</span>
							<button
								class="workspace-group__new"
								onclick={() => startNewSession(group.id)}
								title="New session"
							>
								+
							</button>
						</div>

						{#if group.sessions.length === 0}
							<div class="workspace-group__empty">No sessions</div>
						{:else}
							<ul class="session-list">
								{#each group.sessions as session}
									<li>
										<button
											class="session-list__item"
											class:session-list__item--active={chatStore.sessionId ===
												session.id && chatStore.workspaceId === group.id}
											onclick={() => selectSession(group.id, session.id)}
											title={session.id}
										>
											<span class="session-list__id">
												{session.id.slice(0, 8)}...
											</span>
											<span
												class="session-list__status session-list__status--{session.status}"
											>
												{session.status}
											</span>
										</button>
									</li>
								{/each}
							</ul>
						{/if}
					</div>
				{/each}
			{/if}
		</div>
	</aside>

	<main class="chat-main">
		{#if !hasWorkspace}
			<div class="chat-main__placeholder">
				<h2>Sigil Chat</h2>
				<p>Select a workspace from the sidebar or start a new session to begin.</p>
			</div>
		{:else}
			<div class="chat-main__header">
				<span class="chat-main__workspace">
					{chatStore.workspaceId}
				</span>
				{#if chatStore.sessionId}
					<span class="chat-main__session">
						Session: {chatStore.sessionId.slice(0, 12)}...
					</span>
				{:else}
					<span class="chat-main__session chat-main__session--new">New session</span>
				{/if}
			</div>

			<div class="chat-main__messages" bind:this={messagesContainer}>
				{#if !hasMessages}
					<div class="chat-main__empty">
						Send a message to start the conversation.
					</div>
				{:else}
					{#each chatStore.messages as message (message.id)}
						<ChatMessage {message} />
					{/each}
				{/if}
			</div>

			{#if chatStore.error}
				<div class="chat-main__error">
					{chatStore.error}
					<button
						class="chat-main__error-dismiss"
						onclick={() => (chatStore.error = null)}
					>
						Dismiss
					</button>
				</div>
			{/if}

			<ChatInput
				loading={chatStore.loading}
				onsubmit={handleSend}
				oncancel={handleCancel}
			/>
		{/if}
	</main>
</div>

<style>
	.chat-page {
		display: flex;
		height: 100vh;
		font-family:
			-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		color: #333;
	}

	/* Sidebar */
	.chat-sidebar {
		width: 280px;
		min-width: 280px;
		border-right: 1px solid #e0e0e0;
		background: #fafafa;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.chat-sidebar__header {
		padding: 1rem;
		border-bottom: 1px solid #e0e0e0;
	}

	.chat-sidebar__header h2 {
		margin: 0;
		font-size: 1.1rem;
		font-weight: 600;
	}

	.chat-sidebar__content {
		flex: 1;
		overflow-y: auto;
		padding: 0.5rem;
	}

	.chat-sidebar__loading,
	.chat-sidebar__empty {
		padding: 1rem;
		color: #888;
		font-size: 0.9rem;
		text-align: center;
	}

	/* Workspace groups */
	.workspace-group {
		margin-bottom: 0.75rem;
	}

	.workspace-group__header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.4rem 0.5rem;
	}

	.workspace-group__name {
		font-size: 0.8rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: #666;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.workspace-group__new {
		background: none;
		border: 1px solid #ccc;
		border-radius: 4px;
		width: 22px;
		height: 22px;
		font-size: 0.9rem;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #666;
		padding: 0;
		line-height: 1;
	}

	.workspace-group__new:hover {
		background: #e8e8e8;
		color: #333;
	}

	.workspace-group__empty {
		padding: 0.3rem 0.5rem;
		font-size: 0.8rem;
		color: #aaa;
		font-style: italic;
	}

	/* Session list */
	.session-list {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.session-list__item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 0.4rem 0.5rem;
		border: none;
		background: none;
		cursor: pointer;
		border-radius: 4px;
		font-size: 0.85rem;
		font-family: inherit;
		text-align: left;
		color: #333;
	}

	.session-list__item:hover {
		background: #e8e8e8;
	}

	.session-list__item--active {
		background: #dbeafe;
	}

	.session-list__id {
		font-family: monospace;
		font-size: 0.8rem;
	}

	.session-list__status {
		font-size: 0.7rem;
		padding: 0.1rem 0.3rem;
		border-radius: 3px;
	}

	.session-list__status--active {
		background: #d4edda;
		color: #155724;
	}

	.session-list__status--archived {
		background: #e0e0e0;
		color: #666;
	}

	/* Main chat area */
	.chat-main {
		flex: 1;
		display: flex;
		flex-direction: column;
		overflow: hidden;
		background: #fff;
	}

	.chat-main__placeholder {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		color: #888;
		padding: 2rem;
		text-align: center;
	}

	.chat-main__placeholder h2 {
		margin: 0 0 0.5rem;
		font-size: 1.5rem;
		color: #555;
	}

	.chat-main__placeholder p {
		margin: 0;
		font-size: 0.95rem;
	}

	.chat-main__header {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.75rem 1rem;
		border-bottom: 1px solid #e0e0e0;
		background: #fafafa;
	}

	.chat-main__workspace {
		font-weight: 600;
		font-size: 0.9rem;
	}

	.chat-main__session {
		font-size: 0.8rem;
		color: #666;
		font-family: monospace;
	}

	.chat-main__session--new {
		font-family: inherit;
		font-style: italic;
		color: #4a90d9;
	}

	.chat-main__messages {
		flex: 1;
		overflow-y: auto;
		padding: 1rem;
		display: flex;
		flex-direction: column;
	}

	.chat-main__empty {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #aaa;
		font-size: 0.95rem;
	}

	.chat-main__error {
		padding: 0.5rem 1rem;
		background: #fef2f2;
		border-top: 1px solid #fecaca;
		color: #991b1b;
		font-size: 0.85rem;
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.chat-main__error-dismiss {
		background: none;
		border: 1px solid #fca5a5;
		border-radius: 4px;
		padding: 0.2rem 0.5rem;
		font-size: 0.8rem;
		cursor: pointer;
		color: #991b1b;
		font-family: inherit;
	}

	.chat-main__error-dismiss:hover {
		background: #fee2e2;
	}
</style>

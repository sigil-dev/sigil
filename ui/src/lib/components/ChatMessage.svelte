<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import type { ChatMessage, ToolCall } from '$lib/stores/chat.svelte';

	interface Props {
		message: ChatMessage;
	}

	let { message }: Props = $props();

	let expandedTools = $state<Set<number>>(new Set());

	function toggleTool(index: number): void {
		const next = new Set(expandedTools);
		if (next.has(index)) {
			next.delete(index);
		} else {
			next.add(index);
		}
		expandedTools = next;
	}

	function formatToolStatus(status: ToolCall['status']): string {
		switch (status) {
			case 'pending':
				return 'Pending';
			case 'running':
				return 'Running...';
			case 'complete':
				return 'Complete';
			case 'error':
				return 'Error';
		}
	}

	function formatJson(value: unknown): string {
		try {
			return JSON.stringify(value, null, 2);
		} catch (e) {
			console.warn('formatJson: failed to stringify value', e);
			return String(value);
		}
	}

	const roleLabel = $derived(
		message.role === 'user' ? 'You' : message.role === 'assistant' ? 'Sigil' : 'Tool'
	);

	const roleClass = $derived(`chat-message chat-message--${message.role}`);
</script>

<div class={roleClass}>
	<div class="chat-message__header">
		<span class="chat-message__role">{roleLabel}</span>
		<span class="chat-message__time">
			{new Date(message.timestamp).toLocaleTimeString()}
		</span>
	</div>

	{#if message.content}
		<div class="chat-message__content">
			{message.content}
		</div>
	{/if}

	{#if message.toolCalls && message.toolCalls.length > 0}
		<div class="chat-message__tools">
			{#each message.toolCalls as tool, i}
				<div class="tool-call">
					<button
						class="tool-call__header"
						onclick={() => toggleTool(i)}
						aria-expanded={expandedTools.has(i)}
					>
						<span class="tool-call__indicator">
							{expandedTools.has(i) ? '\u25BC' : '\u25B6'}
						</span>
						<span class="tool-call__name">{tool.name}</span>
						<span class="tool-call__status tool-call__status--{tool.status}">
							{formatToolStatus(tool.status)}
						</span>
					</button>

					{#if expandedTools.has(i)}
						<div class="tool-call__detail">
							{#if tool.input !== undefined}
								<div class="tool-call__section">
									<span class="tool-call__label">Input</span>
									<pre class="tool-call__code">{formatJson(tool.input)}</pre>
								</div>
							{/if}
							{#if tool.result !== undefined}
								<div class="tool-call__section">
									<span class="tool-call__label">Result</span>
									<pre class="tool-call__code">{formatJson(tool.result)}</pre>
								</div>
							{/if}
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.chat-message {
		padding: 0.75rem 1rem;
		border-radius: 8px;
		margin-bottom: 0.5rem;
		max-width: 80%;
	}

	.chat-message--user {
		background: #e8f0fe;
		margin-left: auto;
	}

	.chat-message--assistant {
		background: #f1f3f4;
		margin-right: auto;
	}

	.chat-message--tool {
		background: #fef7e0;
		margin-right: auto;
		font-size: 0.9rem;
	}

	.chat-message__header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.25rem;
	}

	.chat-message__role {
		font-weight: 600;
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: #555;
	}

	.chat-message__time {
		font-size: 0.7rem;
		color: #999;
	}

	.chat-message__content {
		white-space: pre-wrap;
		word-break: break-word;
		line-height: 1.5;
	}

	.chat-message__tools {
		margin-top: 0.5rem;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.tool-call {
		border: 1px solid #ddd;
		border-radius: 4px;
		overflow: hidden;
	}

	.tool-call__header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.6rem;
		width: 100%;
		background: none;
		border: none;
		cursor: pointer;
		font-size: 0.85rem;
		text-align: left;
		font-family: inherit;
	}

	.tool-call__header:hover {
		background: rgba(0, 0, 0, 0.04);
	}

	.tool-call__indicator {
		font-size: 0.65rem;
		color: #666;
	}

	.tool-call__name {
		font-family: monospace;
		font-weight: 500;
	}

	.tool-call__status {
		margin-left: auto;
		font-size: 0.75rem;
		padding: 0.1rem 0.4rem;
		border-radius: 3px;
	}

	.tool-call__status--pending {
		background: #e0e0e0;
		color: #666;
	}

	.tool-call__status--running {
		background: #fff3cd;
		color: #856404;
	}

	.tool-call__status--complete {
		background: #d4edda;
		color: #155724;
	}

	.tool-call__status--error {
		background: #f8d7da;
		color: #721c24;
	}

	.tool-call__detail {
		padding: 0.5rem 0.6rem;
		border-top: 1px solid #eee;
		background: rgba(0, 0, 0, 0.02);
	}

	.tool-call__section {
		margin-bottom: 0.4rem;
	}

	.tool-call__section:last-child {
		margin-bottom: 0;
	}

	.tool-call__label {
		display: block;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		color: #888;
		margin-bottom: 0.2rem;
	}

	.tool-call__code {
		background: #f8f9fa;
		border: 1px solid #e9ecef;
		border-radius: 3px;
		padding: 0.4rem;
		font-size: 0.8rem;
		overflow-x: auto;
		margin: 0;
		white-space: pre-wrap;
		word-break: break-word;
	}
</style>

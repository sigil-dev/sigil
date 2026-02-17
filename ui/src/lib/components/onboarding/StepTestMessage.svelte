<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	interface Props {
		message: string;
		loading: boolean;
		error: string | null;
		valid: boolean | null;
		response: string | null;
		onmessagechange: (message: string) => void;
		onsend: () => void;
	}

	let { message, loading, error, valid, response, onmessagechange, onsend }: Props = $props();

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			onsend();
		}
	}
</script>

<div class="step-test">
	<h2>Send your first message</h2>
	<p class="step-description">
		Test the connection by sending a message through the agent pipeline. This verifies your
		provider is working end-to-end.
	</p>

	<div class="form-group">
		<label for="test-message-input">Test Message</label>
		<textarea
			id="test-message-input"
			placeholder="Hello, Sigil!"
			value={message}
			oninput={(e) => onmessagechange(e.currentTarget.value)}
			onkeydown={handleKeydown}
			disabled={loading}
			rows={3}
		></textarea>
	</div>

	<div class="actions">
		<button class="btn btn--primary" onclick={onsend} disabled={loading || !message.trim()}>
			{#if loading}
				<span class="spinner"></span>
				Sending...
			{:else}
				Send Test Message
			{/if}
		</button>
	</div>

	{#if error}
		<div class="feedback feedback--error">{error}</div>
	{/if}

	{#if valid === true && response}
		<div class="feedback feedback--success">{response}</div>
	{/if}
</div>

<style>
	.step-test {
		max-width: 480px;
	}

	h2 {
		font-size: 1.5rem;
		margin: 0 0 0.5rem;
	}

	.step-description {
		color: #666;
		margin-bottom: 1.5rem;
		line-height: 1.5;
	}

	.form-group {
		margin-bottom: 1.25rem;
	}

	.form-group label {
		display: block;
		font-weight: 600;
		font-size: 0.9rem;
		margin-bottom: 0.35rem;
		color: #333;
	}

	.form-group textarea {
		width: 100%;
		padding: 0.6rem 0.75rem;
		border: 1px solid #ccc;
		border-radius: 6px;
		font-size: 0.95rem;
		font-family: inherit;
		outline: none;
		resize: vertical;
		box-sizing: border-box;
		line-height: 1.4;
	}

	.form-group textarea:focus {
		border-color: #4a90d9;
		box-shadow: 0 0 0 2px rgba(74, 144, 217, 0.2);
	}

	.form-group textarea:disabled {
		background: #f5f5f5;
		color: #999;
	}

	.actions {
		margin-bottom: 1rem;
	}

	.btn {
		padding: 0.6rem 1.25rem;
		border: none;
		border-radius: 6px;
		font-size: 0.95rem;
		font-family: inherit;
		cursor: pointer;
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
	}

	.btn--primary {
		background: #4a90d9;
		color: #fff;
	}

	.btn--primary:hover:not(:disabled) {
		background: #3a7bc8;
	}

	.btn--primary:disabled {
		background: #b0c4de;
		cursor: not-allowed;
	}

	.feedback {
		padding: 0.75rem 1rem;
		border-radius: 6px;
		font-size: 0.9rem;
		margin-top: 0.5rem;
	}

	.feedback--error {
		background: #fef2f2;
		color: #991b1b;
		border: 1px solid #fecaca;
	}

	.feedback--success {
		background: #f0fdf4;
		color: #166534;
		border: 1px solid #bbf7d0;
	}

	.spinner {
		display: inline-block;
		width: 14px;
		height: 14px;
		border: 2px solid rgba(255, 255, 255, 0.4);
		border-top-color: #fff;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
</style>

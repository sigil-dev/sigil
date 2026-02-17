<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	interface Props {
		botToken: string;
		loading: boolean;
		error: string | null;
		valid: boolean | null;
		ontokenchange: (token: string) => void;
		onvalidate: () => void;
		onskip: () => void;
	}

	let { botToken, loading, error, valid, ontokenchange, onvalidate, onskip }: Props = $props();

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter') {
			e.preventDefault();
			onvalidate();
		}
	}
</script>

<div class="step-channel">
	<h2>Add a channel</h2>
	<p class="step-description">
		Connect a messaging platform so users can interact with your agent. Start with a Telegram bot.
	</p>

	<div class="form-group">
		<label for="bot-token-input">Telegram Bot Token</label>
		<input
			id="bot-token-input"
			type="password"
			placeholder="123456789:ABCdefGHIjklMNOpqrSTUvwxYZ..."
			value={botToken}
			oninput={(e) => ontokenchange(e.currentTarget.value)}
			onkeydown={handleKeydown}
			disabled={loading}
			autocomplete="off"
		/>
		<p class="form-hint">
			Create a bot via <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer"
				>@BotFather</a
			> on Telegram to get your token.
		</p>
	</div>

	<div class="actions">
		<button class="btn btn--primary" onclick={onvalidate} disabled={loading || !botToken.trim()}>
			{#if loading}
				<span class="spinner"></span>
				Validating...
			{:else}
				Validate Token
			{/if}
		</button>
		<button class="btn btn--secondary" onclick={onskip} disabled={loading}>
			Skip for now
		</button>
	</div>

	{#if error}
		<div class="feedback feedback--error">{error}</div>
	{/if}

	{#if valid === true}
		<div class="feedback feedback--success">Telegram bot token validated successfully.</div>
	{/if}
</div>

<style>
	.step-channel {
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

	.form-group input {
		width: 100%;
		padding: 0.6rem 0.75rem;
		border: 1px solid #ccc;
		border-radius: 6px;
		font-size: 0.95rem;
		font-family: inherit;
		outline: none;
		box-sizing: border-box;
	}

	.form-group input:focus {
		border-color: #4a90d9;
		box-shadow: 0 0 0 2px rgba(74, 144, 217, 0.2);
	}

	.form-group input:disabled {
		background: #f5f5f5;
		color: #999;
	}

	.form-hint {
		font-size: 0.8rem;
		color: #888;
		margin-top: 0.35rem;
	}

	.form-hint a {
		color: #4a90d9;
		text-decoration: none;
	}

	.form-hint a:hover {
		text-decoration: underline;
	}

	.actions {
		display: flex;
		gap: 0.75rem;
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

	.btn--secondary {
		background: #f0f0f0;
		color: #333;
		border: 1px solid #ccc;
	}

	.btn--secondary:hover:not(:disabled) {
		background: #e0e0e0;
	}

	.btn--secondary:disabled {
		opacity: 0.5;
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

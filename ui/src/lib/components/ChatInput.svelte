<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	interface Props {
		loading: boolean;
		disabled?: boolean;
		onsubmit: (content: string) => void;
		oncancel?: () => void;
	}

	let { loading, disabled = false, onsubmit, oncancel }: Props = $props();

	let inputValue = $state('');

	function handleSubmit(e: Event): void {
		e.preventDefault();
		const trimmed = inputValue.trim();
		if (!trimmed || loading || disabled) return;
		onsubmit(trimmed);
		inputValue = '';
	}

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			handleSubmit(e);
		}
	}

	function handleCancel(): void {
		if (oncancel) oncancel();
	}
</script>

<form class="chat-input" onsubmit={handleSubmit}>
	<div class="chat-input__wrapper">
		<div class="chat-input__left-actions">
			<button
				type="button"
				class="chat-input__btn chat-input__btn--attach"
				disabled
				title="Attach file (coming soon)"
			>
				&#x1F4CE;
			</button>
		</div>

		<textarea
			class="chat-input__field"
			placeholder="Type a message..."
			bind:value={inputValue}
			onkeydown={handleKeydown}
			disabled={disabled || loading}
			rows={1}
		></textarea>

		<div class="chat-input__actions">
			{#if loading}
				<button
					type="button"
					class="chat-input__btn chat-input__btn--cancel"
					onclick={handleCancel}
					title="Cancel"
				>
					<span class="chat-input__spinner"></span>
					Stop
				</button>
			{:else}
				<button
					type="submit"
					class="chat-input__btn chat-input__btn--send"
					disabled={!inputValue.trim() || disabled}
					title="Send message"
				>
					Send
				</button>
			{/if}
		</div>
	</div>
</form>

<style>
	.chat-input {
		padding: 0.75rem 1rem;
		border-top: 1px solid #e0e0e0;
		background: #fff;
	}

	.chat-input__wrapper {
		display: flex;
		gap: 0.5rem;
		align-items: flex-end;
	}

	.chat-input__left-actions {
		display: flex;
		align-items: center;
	}

	.chat-input__btn--attach {
		background: none;
		border: 1px solid #ccc;
		border-radius: 6px;
		padding: 0.4rem 0.5rem;
		font-size: 1rem;
		cursor: not-allowed;
		opacity: 0.5;
	}

	.chat-input__field {
		flex: 1;
		resize: none;
		border: 1px solid #ccc;
		border-radius: 8px;
		padding: 0.6rem 0.75rem;
		font-size: 0.95rem;
		font-family: inherit;
		line-height: 1.4;
		outline: none;
		min-height: 2.4rem;
		max-height: 8rem;
		overflow-y: auto;
	}

	.chat-input__field:focus {
		border-color: #4a90d9;
		box-shadow: 0 0 0 2px rgba(74, 144, 217, 0.2);
	}

	.chat-input__field:disabled {
		background: #f5f5f5;
		color: #999;
	}

	.chat-input__actions {
		display: flex;
		align-items: center;
	}

	.chat-input__btn {
		padding: 0.5rem 1rem;
		border: none;
		border-radius: 6px;
		font-size: 0.9rem;
		font-family: inherit;
		cursor: pointer;
		white-space: nowrap;
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}

	.chat-input__btn--send {
		background: #4a90d9;
		color: #fff;
	}

	.chat-input__btn--send:hover:not(:disabled) {
		background: #3a7bc8;
	}

	.chat-input__btn--send:disabled {
		background: #b0c4de;
		cursor: not-allowed;
	}

	.chat-input__btn--cancel {
		background: #e0e0e0;
		color: #333;
	}

	.chat-input__btn--cancel:hover {
		background: #d0d0d0;
	}

	.chat-input__spinner {
		display: inline-block;
		width: 14px;
		height: 14px;
		border: 2px solid #999;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
</style>

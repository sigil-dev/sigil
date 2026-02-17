<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import type { ProviderType } from '$lib/stores/onboarding.svelte';

	interface Props {
		providerType: ProviderType;
		apiKey: string;
		loading: boolean;
		error: string | null;
		valid: boolean | null;
		onproviderchange: (type: ProviderType) => void;
		onkeychange: (key: string) => void;
		onvalidate: () => void;
	}

	let {
		providerType,
		apiKey,
		loading,
		error,
		valid,
		onproviderchange,
		onkeychange,
		onvalidate
	}: Props = $props();

	const providers: { value: ProviderType; label: string; placeholder: string }[] = [
		{ value: 'anthropic', label: 'Anthropic (Claude)', placeholder: 'sk-ant-...' },
		{ value: 'openai', label: 'OpenAI (GPT)', placeholder: 'sk-...' },
		{ value: 'google', label: 'Google (Gemini)', placeholder: 'AIza...' }
	];

	const currentProvider = $derived(providers.find((p) => p.value === providerType) ?? providers[0]);

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter') {
			e.preventDefault();
			onvalidate();
		}
	}
</script>

<div class="step-provider">
	<h2>Add your first provider</h2>
	<p class="step-description">
		Sigil needs an LLM provider to power conversations. Paste your API key below.
	</p>

	<div class="form-group">
		<label for="provider-select">Provider</label>
		<select
			id="provider-select"
			value={providerType}
			onchange={(e) => onproviderchange(e.currentTarget.value as ProviderType)}
			disabled={loading}
		>
			{#each providers as p}
				<option value={p.value}>{p.label}</option>
			{/each}
		</select>
	</div>

	<div class="form-group">
		<label for="api-key-input">API Key</label>
		<input
			id="api-key-input"
			type="password"
			placeholder={currentProvider.placeholder}
			value={apiKey}
			oninput={(e) => onkeychange(e.currentTarget.value)}
			onkeydown={handleKeydown}
			disabled={loading}
			autocomplete="off"
		/>
	</div>

	<div class="actions">
		<button class="btn btn--primary" onclick={onvalidate} disabled={loading || !apiKey.trim()}>
			{#if loading}
				<span class="spinner"></span>
				Validating...
			{:else}
				Validate Key
			{/if}
		</button>
	</div>

	{#if error}
		<div class="feedback feedback--error">{error}</div>
	{/if}

	{#if valid === true}
		<div class="feedback feedback--success">Provider key validated successfully.</div>
	{/if}
</div>

<style>
	.step-provider {
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

	.form-group select,
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

	.form-group select:focus,
	.form-group input:focus {
		border-color: #4a90d9;
		box-shadow: 0 0 0 2px rgba(74, 144, 217, 0.2);
	}

	.form-group select:disabled,
	.form-group input:disabled {
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

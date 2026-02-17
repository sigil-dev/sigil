<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	interface Props {
		oncomplete: () => void;
	}

	let { oncomplete }: Props = $props();
</script>

<div class="step-done">
	<div class="done-icon">&#10003;</div>
	<h2>All set!</h2>
	<p class="step-description">
		Sigil is configured and ready. Your provider is connected and you can start having
		conversations with your AI agent.
	</p>

	<div class="summary">
		<h3>What's next?</h3>
		<ul>
			<li>Chat with your agent from the <strong>Chat</strong> page</li>
			<li>Manage providers and settings from <strong>Settings</strong></li>
			<li>Install additional plugins from <strong>Plugins</strong></li>
			<li>Create workspaces to organize conversations</li>
		</ul>
	</div>

	<div class="actions">
		<button class="btn btn--primary" onclick={oncomplete}> Start Using Sigil </button>
	</div>
</div>

<style>
	.step-done {
		max-width: 480px;
		text-align: center;
	}

	.done-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 64px;
		height: 64px;
		background: #d4edda;
		color: #155724;
		border-radius: 50%;
		font-size: 2rem;
		margin-bottom: 1rem;
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

	.summary {
		text-align: left;
		background: #f8f9fa;
		border: 1px solid #e9ecef;
		border-radius: 8px;
		padding: 1.25rem 1.5rem;
		margin-bottom: 1.5rem;
	}

	.summary h3 {
		font-size: 1rem;
		margin: 0 0 0.75rem;
		color: #333;
	}

	.summary ul {
		margin: 0;
		padding-left: 1.25rem;
	}

	.summary li {
		margin-bottom: 0.4rem;
		font-size: 0.9rem;
		color: #555;
		line-height: 1.4;
	}

	.actions {
		margin-top: 1rem;
	}

	.btn {
		padding: 0.75rem 2rem;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-family: inherit;
		cursor: pointer;
	}

	.btn--primary {
		background: #4a90d9;
		color: #fff;
	}

	.btn--primary:hover {
		background: #3a7bc8;
	}
</style>

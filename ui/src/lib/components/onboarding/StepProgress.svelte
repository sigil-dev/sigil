<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import {
		ONBOARDING_STEPS,
		STEP_LABELS,
		type OnboardingStep
	} from '$lib/stores/onboarding.svelte';
	import type { ValidationResult } from '$lib/stores/onboarding.svelte';

	interface Props {
		currentStep: OnboardingStep;
		validation: Record<OnboardingStep, ValidationResult | null>;
	}

	let { currentStep, validation }: Props = $props();

	function stepState(
		step: OnboardingStep
	): 'complete' | 'current' | 'upcoming' {
		const currentIdx = ONBOARDING_STEPS.indexOf(currentStep);
		const stepIdx = ONBOARDING_STEPS.indexOf(step);

		if (stepIdx < currentIdx) return 'complete';
		if (stepIdx === currentIdx) return 'current';
		return 'upcoming';
	}
</script>

<nav class="step-progress" aria-label="Onboarding progress">
	<ol class="step-list">
		{#each ONBOARDING_STEPS as step, i}
			{@const state = stepState(step)}
			{@const isValid = validation[step]?.valid === true}
			<li class="step-item step-item--{state}" class:step-item--valid={isValid}>
				<div class="step-indicator">
					{#if state === 'complete' || isValid}
						<span class="step-check">&#10003;</span>
					{:else}
						<span class="step-number">{i + 1}</span>
					{/if}
				</div>
				<span class="step-label">{STEP_LABELS[step]}</span>
			</li>
		{/each}
	</ol>
</nav>

<style>
	.step-progress {
		margin-bottom: 2rem;
	}

	.step-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		gap: 0;
	}

	.step-item {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		position: relative;
		text-align: center;
	}

	/* Connector line between steps */
	.step-item:not(:last-child)::after {
		content: '';
		position: absolute;
		top: 16px;
		left: calc(50% + 16px);
		right: calc(-50% + 16px);
		height: 2px;
		background: #ddd;
	}

	.step-item--complete:not(:last-child)::after,
	.step-item--valid:not(:last-child)::after {
		background: #4a90d9;
	}

	.step-indicator {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 0.85rem;
		font-weight: 600;
		margin-bottom: 0.4rem;
		position: relative;
		z-index: 1;
	}

	.step-item--upcoming .step-indicator {
		background: #f0f0f0;
		color: #999;
		border: 2px solid #ddd;
	}

	.step-item--current .step-indicator {
		background: #4a90d9;
		color: #fff;
		border: 2px solid #4a90d9;
	}

	.step-item--complete .step-indicator,
	.step-item--valid .step-indicator {
		background: #d4edda;
		color: #155724;
		border: 2px solid #155724;
	}

	.step-label {
		font-size: 0.75rem;
		color: #888;
		max-width: 100px;
		line-height: 1.3;
	}

	.step-item--current .step-label {
		color: #333;
		font-weight: 600;
	}

	.step-item--complete .step-label,
	.step-item--valid .step-label {
		color: #555;
	}

	.step-check {
		font-size: 0.9rem;
	}

	.step-number {
		font-size: 0.85rem;
	}
</style>

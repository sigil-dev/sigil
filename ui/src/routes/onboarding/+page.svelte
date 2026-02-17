<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Sigil Contributors -->
<script lang="ts">
	import { goto } from '$app/navigation';
	import StepProgress from '$lib/components/onboarding/StepProgress.svelte';
	import StepProvider from '$lib/components/onboarding/StepProvider.svelte';
	import StepChannel from '$lib/components/onboarding/StepChannel.svelte';
	import StepTestMessage from '$lib/components/onboarding/StepTestMessage.svelte';
	import StepDone from '$lib/components/onboarding/StepDone.svelte';
	import { onboardingStore, type ProviderType } from '$lib/stores/onboarding.svelte';

	const providerValid = $derived(onboardingStore.stepValidation.provider?.valid ?? null);
	const channelValid = $derived(onboardingStore.stepValidation.channel?.valid ?? null);
	const testValid = $derived(onboardingStore.stepValidation['test-message']?.valid ?? null);

	function handleProviderChange(type: ProviderType): void {
		onboardingStore.providerType = type;
	}

	function handleKeyChange(key: string): void {
		onboardingStore.providerApiKey = key;
	}

	function handleTokenChange(token: string): void {
		onboardingStore.channelBotToken = token;
	}

	function handleMessageChange(message: string): void {
		onboardingStore.testMessage = message;
	}

	function handleValidateProvider(): void {
		onboardingStore.validateProvider();
	}

	function handleValidateChannel(): void {
		onboardingStore.validateChannel();
	}

	function handleSkipChannel(): void {
		onboardingStore.goNext();
	}

	function handleSendTest(): void {
		onboardingStore.sendTest();
	}

	function handleComplete(): void {
		onboardingStore.complete();
		goto('/chat');
	}

	function handleBack(): void {
		onboardingStore.goBack();
	}

	function handleNext(): void {
		onboardingStore.goNext();
	}
</script>

<div class="onboarding-page">
	<div class="onboarding-container">
		<div class="onboarding-header">
			<h1>Welcome to Sigil</h1>
			<p>Let's get your AI gateway set up in a few quick steps.</p>
		</div>

		<StepProgress
			currentStep={onboardingStore.currentStep}
			validation={onboardingStore.stepValidation}
		/>

		<div class="onboarding-content">
			{#if onboardingStore.currentStep === 'provider'}
				<StepProvider
					providerType={onboardingStore.providerType}
					apiKey={onboardingStore.providerApiKey}
					loading={onboardingStore.loading}
					error={onboardingStore.error}
					valid={providerValid}
					onproviderchange={handleProviderChange}
					onkeychange={handleKeyChange}
					onvalidate={handleValidateProvider}
				/>
			{:else if onboardingStore.currentStep === 'channel'}
				<StepChannel
					botToken={onboardingStore.channelBotToken}
					loading={onboardingStore.loading}
					error={onboardingStore.error}
					valid={channelValid}
					ontokenchange={handleTokenChange}
					onvalidate={handleValidateChannel}
					onskip={handleSkipChannel}
				/>
			{:else if onboardingStore.currentStep === 'test-message'}
				<StepTestMessage
					message={onboardingStore.testMessage}
					loading={onboardingStore.loading}
					error={onboardingStore.error}
					valid={testValid}
					response={onboardingStore.testResponse}
					onmessagechange={handleMessageChange}
					onsend={handleSendTest}
				/>
			{:else if onboardingStore.currentStep === 'done'}
				<StepDone oncomplete={handleComplete} />
			{/if}
		</div>

		{#if onboardingStore.currentStep !== 'done'}
			<div class="onboarding-nav">
				<button
					class="nav-btn nav-btn--back"
					onclick={handleBack}
					disabled={!onboardingStore.canGoBack}
				>
					Back
				</button>
				<button
					class="nav-btn nav-btn--next"
					onclick={handleNext}
					disabled={!onboardingStore.canGoNext}
				>
					Next
				</button>
			</div>
		{/if}
	</div>
</div>

<style>
	.onboarding-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: #f8f9fa;
		font-family:
			-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		color: #333;
		padding: 2rem;
	}

	.onboarding-container {
		width: 100%;
		max-width: 640px;
		background: #fff;
		border-radius: 12px;
		box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);
		padding: 2.5rem;
	}

	.onboarding-header {
		text-align: center;
		margin-bottom: 2rem;
	}

	.onboarding-header h1 {
		font-size: 1.75rem;
		margin: 0 0 0.5rem;
		color: #1a1a1a;
	}

	.onboarding-header p {
		color: #666;
		font-size: 1rem;
		margin: 0;
	}

	.onboarding-content {
		min-height: 280px;
		display: flex;
		flex-direction: column;
		justify-content: flex-start;
	}

	.onboarding-nav {
		display: flex;
		justify-content: space-between;
		margin-top: 2rem;
		padding-top: 1.5rem;
		border-top: 1px solid #e9ecef;
	}

	.nav-btn {
		padding: 0.6rem 1.5rem;
		border-radius: 6px;
		font-size: 0.95rem;
		font-family: inherit;
		cursor: pointer;
	}

	.nav-btn--back {
		background: none;
		border: 1px solid #ccc;
		color: #666;
	}

	.nav-btn--back:hover:not(:disabled) {
		background: #f5f5f5;
		color: #333;
	}

	.nav-btn--back:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.nav-btn--next {
		background: #4a90d9;
		border: none;
		color: #fff;
	}

	.nav-btn--next:hover:not(:disabled) {
		background: #3a7bc8;
	}

	.nav-btn--next:disabled {
		background: #b0c4de;
		cursor: not-allowed;
	}
</style>

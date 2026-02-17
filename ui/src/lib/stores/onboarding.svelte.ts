// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { api } from "$lib/api/client";
import { logger } from "$lib/logger";
import { classifyError } from "./classify-error";

/** Onboarding wizard step identifiers */
export type OnboardingStep = "provider" | "channel" | "test-message" | "done";

/** All steps in order */
export const ONBOARDING_STEPS: readonly OnboardingStep[] = [
  "provider",
  "channel",
  "test-message",
  "done",
] as const;

/** Human-readable labels for each step */
export const STEP_LABELS: Record<OnboardingStep, string> = {
  provider: "Add your first provider",
  channel: "Add a channel",
  "test-message": "Send your first message",
  done: "All set!",
};

/** localStorage key for onboarding completion flag */
const ONBOARDING_COMPLETE_KEY = "sigil:onboarding:complete";

/** Supported provider types */
export type ProviderType = "anthropic" | "openai" | "google" | "openrouter";

/** Provider configuration for the wizard */
export interface ProviderConfig {
  type: ProviderType;
  apiKey: string;
  label: string;
}

/** Channel configuration for the wizard */
export interface ChannelConfig {
  type: "telegram";
  botToken: string;
  label: string;
}

/** Result of a validation attempt */
export interface ValidationResult {
  valid: boolean;
  message: string;
}

/** Safe localStorage accessor — returns null in environments without localStorage */
function getStorage(): Storage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** Check if onboarding has been completed */
export function isOnboardingComplete(): boolean {
  const storage = getStorage();
  if (!storage) return true;
  return storage.getItem(ONBOARDING_COMPLETE_KEY) === "true";
}

/** Mark onboarding as complete */
export function markOnboardingComplete(): void {
  const storage = getStorage();
  if (!storage) return;
  storage.setItem(ONBOARDING_COMPLETE_KEY, "true");
}

/** Reset onboarding state (for testing or re-running) */
export function resetOnboarding(): void {
  const storage = getStorage();
  if (!storage) return;
  storage.removeItem(ONBOARDING_COMPLETE_KEY);
}

/**
 * Detect first-run state by checking if any providers are configured.
 * Uses the list-plugins endpoint and looks for provider-type plugins.
 */
export async function detectFirstRun(): Promise<boolean> {
  if (isOnboardingComplete()) return false;

  try {
    const { data, error: err } = await api.GET("/api/v1/plugins");
    if (err) {
      // If we can't reach the gateway, assume first run
      logger.warn("Failed to detect first-run state", { error: err });
      return true;
    }

    const plugins = data?.plugins ?? [];
    const hasProvider = plugins.some((p) => p.type === "provider" && p.status === "running");
    return !hasProvider;
  } catch (error) {
    logger.warn("Failed to detect first-run state", { error });
    return true;
  }
}

/**
 * Validate a provider API key and persist it via the backend.
 * Client-side format checks run first as a quick gate, then the backend
 * validates against the provider API and stores the key in the OS keyring.
 */
export async function validateProviderKey(config: ProviderConfig): Promise<ValidationResult> {
  const { type, apiKey } = config;

  // Basic format validation (quick client-side gate)
  if (!apiKey.trim()) {
    return { valid: false, message: "API key is required" };
  }

  // Provider-specific key format checks
  switch (type) {
    case "anthropic":
      if (!apiKey.startsWith("sk-ant-")) {
        return { valid: false, message: "Anthropic API keys start with 'sk-ant-'" };
      }
      break;
    case "openai":
      if (!apiKey.startsWith("sk-")) {
        return { valid: false, message: "OpenAI API keys start with 'sk-'" };
      }
      break;
    case "google":
      if (apiKey.length < 20) {
        return { valid: false, message: "Google API key appears too short" };
      }
      break;
  }

  // Validate and persist via backend
  try {
    const { data, error: err } = await api.POST("/api/v1/config/providers", {
      body: { type, api_key: apiKey },
    });
    if (err) {
      const detail = (err as { detail?: string })?.detail ?? "Validation failed";
      return { valid: false, message: detail };
    }
    return { valid: true, message: `${data?.provider ?? type} API key validated and saved` };
  } catch {
    return { valid: false, message: "Cannot reach gateway — is it running?" };
  }
}

/**
 * Validate a Telegram bot token and persist it via the backend.
 * Client-side format checks run first, then the backend validates
 * against the Telegram API and stores the token in the OS keyring.
 */
export async function validateChannelToken(config: ChannelConfig): Promise<ValidationResult> {
  const { type, botToken } = config;

  if (!botToken.trim()) {
    return { valid: false, message: "Bot token is required" };
  }

  // Telegram bot token format: <number>:<alphanumeric string>
  const telegramTokenPattern = /^\d+:[A-Za-z0-9_-]{35,}$/;
  if (!telegramTokenPattern.test(botToken.trim())) {
    return {
      valid: false,
      message: "Invalid Telegram bot token format. Expected: 123456:ABC-DEF...",
    };
  }

  // Validate and persist via backend
  try {
    const { data, error: err } = await api.POST("/api/v1/config/channels", {
      body: { type, bot_token: botToken },
    });
    if (err) {
      const detail = (err as { detail?: string })?.detail ?? "Validation failed";
      return { valid: false, message: detail };
    }
    return { valid: true, message: `${data?.channel ?? type} bot token validated and saved` };
  } catch {
    return { valid: false, message: "Cannot reach gateway — is it running?" };
  }
}

/**
 * Send a test message through the gateway to verify the full pipeline.
 */
export async function sendTestMessage(content: string): Promise<ValidationResult> {
  if (!content.trim()) {
    return { valid: false, message: "Message content is required" };
  }

  try {
    const { response, error } = await api.POST("/api/v1/chat/stream", {
      body: { content: content.trim() },
    });

    if (error || !response.ok) {
      const detail = (error as { detail?: string })?.detail ?? `HTTP ${response.status}`;
      return { valid: false, message: `Message failed: ${detail}` };
    }

    return { valid: true, message: "Message sent successfully" };
  } catch (error) {
    const classified = classifyError(error);
    return { valid: false, message: classified.message };
  }
}

/**
 * Onboarding store using Svelte 5 runes for reactivity.
 * Manages the 4-step onboarding wizard state.
 */
export class OnboardingStore {
  currentStep = $state<OnboardingStep>("provider");
  loading = $state(false);
  error = $state<string | null>(null);
  stepValidation = $state<Record<OnboardingStep, ValidationResult | null>>({
    provider: null,
    channel: null,
    "test-message": null,
    done: null,
  });

  // Provider config state
  providerType = $state<ProviderType>("anthropic");
  providerApiKey = $state("");

  // Channel config state
  channelBotToken = $state("");

  // Test message state
  testMessage = $state("Hello, Sigil!");
  testResponse = $state<string | null>(null);

  /** Current step index (0-based) */
  get currentStepIndex(): number {
    return ONBOARDING_STEPS.indexOf(this.currentStep);
  }

  /** Whether we can go back */
  get canGoBack(): boolean {
    return this.currentStepIndex > 0;
  }

  /** Whether we can go forward (step must be validated or skippable) */
  get canGoNext(): boolean {
    const step = this.currentStep;
    if (step === "done") return false;

    // Channel step is skippable
    if (step === "channel") return true;

    const validation = this.stepValidation[step];
    return validation?.valid === true;
  }

  /** Whether the current step has been validated */
  get isCurrentStepValid(): boolean {
    return this.stepValidation[this.currentStep]?.valid === true;
  }

  /** Go to previous step */
  goBack(): void {
    if (!this.canGoBack) return;
    const idx = this.currentStepIndex;
    this.currentStep = ONBOARDING_STEPS[idx - 1];
    this.error = null;
  }

  /** Go to next step */
  goNext(): void {
    if (!this.canGoNext) return;
    const idx = this.currentStepIndex;
    this.currentStep = ONBOARDING_STEPS[idx + 1];
    this.error = null;
  }

  /** Go to a specific step */
  goToStep(step: OnboardingStep): void {
    this.currentStep = step;
    this.error = null;
  }

  /** Validate the provider configuration */
  async validateProvider(): Promise<void> {
    this.loading = true;
    this.error = null;

    try {
      const result = await validateProviderKey({
        type: this.providerType,
        apiKey: this.providerApiKey,
        label: `${this.providerType}-default`,
      });
      this.stepValidation = { ...this.stepValidation, provider: result };
      if (!result.valid) {
        this.error = result.message;
      }
    } catch (error) {
      logger.error("Provider validation failed", { error });
      this.error = "Validation failed unexpectedly";
      this.stepValidation = {
        ...this.stepValidation,
        provider: { valid: false, message: "Validation failed unexpectedly" },
      };
    } finally {
      this.loading = false;
    }
  }

  /** Validate the channel configuration */
  async validateChannel(): Promise<void> {
    this.loading = true;
    this.error = null;

    try {
      const result = await validateChannelToken({
        type: "telegram",
        botToken: this.channelBotToken,
        label: "telegram-default",
      });
      this.stepValidation = { ...this.stepValidation, channel: result };
      if (!result.valid) {
        this.error = result.message;
      }
    } catch (error) {
      logger.error("Channel validation failed", { error });
      this.error = "Validation failed unexpectedly";
      this.stepValidation = {
        ...this.stepValidation,
        channel: { valid: false, message: "Validation failed unexpectedly" },
      };
    } finally {
      this.loading = false;
    }
  }

  /** Send a test message */
  async sendTest(): Promise<void> {
    this.loading = true;
    this.error = null;
    this.testResponse = null;

    try {
      const result = await sendTestMessage(this.testMessage);
      this.stepValidation = { ...this.stepValidation, "test-message": result };
      if (!result.valid) {
        this.error = result.message;
      } else {
        this.testResponse = result.message;
      }
    } catch (error) {
      logger.error("Test message failed", { error });
      this.error = "Test message failed unexpectedly";
      this.stepValidation = {
        ...this.stepValidation,
        "test-message": { valid: false, message: "Test message failed unexpectedly" },
      };
    } finally {
      this.loading = false;
    }
  }

  /** Complete onboarding and mark as done */
  complete(): void {
    markOnboardingComplete();
    this.stepValidation = {
      ...this.stepValidation,
      done: { valid: true, message: "Onboarding complete" },
    };
  }

  /** Reset the entire onboarding state */
  reset(): void {
    this.currentStep = "provider";
    this.loading = false;
    this.error = null;
    this.stepValidation = {
      provider: null,
      channel: null,
      "test-message": null,
      done: null,
    };
    this.providerType = "anthropic";
    this.providerApiKey = "";
    this.channelBotToken = "";
    this.testMessage = "Hello, Sigil!";
    this.testResponse = null;
    resetOnboarding();
  }
}

/** Singleton onboarding store */
export const onboardingStore = new OnboardingStore();

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the api module before importing
vi.mock("$lib/api/client", () => ({
  api: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
  API_BASE: "http://localhost:18789",
}));

vi.stubEnv("VITE_API_URL", "http://localhost:18789");

import { api } from "$lib/api/client";
import {
  detectFirstRun,
  isOnboardingComplete,
  markOnboardingComplete,
  OnboardingStore,
  ONBOARDING_STEPS,
  resetOnboarding,
  sendTestMessage,
  STEP_LABELS,
  validateChannelToken,
  validateProviderKey,
} from "./onboarding.svelte";

// Mock localStorage with a fresh store per test
function createLocalStorageMock() {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: vi.fn((i: number) => Object.keys(store)[i] ?? null),
  };
}

describe("onboarding store", () => {
  let storageMock: ReturnType<typeof createLocalStorageMock>;

  beforeEach(() => {
    vi.restoreAllMocks();
    storageMock = createLocalStorageMock();
    Object.defineProperty(globalThis, "localStorage", {
      value: storageMock,
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("constants", () => {
    it("has 4 steps in order", () => {
      expect(ONBOARDING_STEPS).toEqual(["provider", "channel", "test-message", "done"]);
    });

    it("has labels for all steps", () => {
      for (const step of ONBOARDING_STEPS) {
        expect(STEP_LABELS[step]).toBeDefined();
        expect(typeof STEP_LABELS[step]).toBe("string");
      }
    });
  });

  describe("isOnboardingComplete / markOnboardingComplete / resetOnboarding", () => {
    it("returns false when not complete", () => {
      expect(isOnboardingComplete()).toBe(false);
    });

    it("returns true after marking complete", () => {
      markOnboardingComplete();
      expect(isOnboardingComplete()).toBe(true);
    });

    it("returns false after reset", () => {
      markOnboardingComplete();
      resetOnboarding();
      expect(isOnboardingComplete()).toBe(false);
    });
  });

  describe("detectFirstRun", () => {
    it("returns false when onboarding already completed", async () => {
      markOnboardingComplete();
      const result = await detectFirstRun();
      expect(result).toBe(false);
    });

    it("returns true when no provider plugins found", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: { plugins: [] },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      const result = await detectFirstRun();
      expect(result).toBe(true);
    });

    it("returns false when a running provider plugin exists", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: {
          plugins: [
            { name: "anthropic", type: "provider", status: "running", version: "1.0.0" },
          ],
        },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      const result = await detectFirstRun();
      expect(result).toBe(false);
    });

    it("returns true when API call fails", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockRejectedValue(new Error("Network error"));

      const result = await detectFirstRun();
      expect(result).toBe(true);
    });

    it("returns true when only non-provider plugins exist", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: {
          plugins: [
            { name: "telegram", type: "channel", status: "running", version: "1.0.0" },
          ],
        },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      const result = await detectFirstRun();
      expect(result).toBe(true);
    });
  });

  describe("validateProviderKey", () => {
    it("rejects empty key", async () => {
      const result = await validateProviderKey({
        type: "anthropic",
        apiKey: "",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("required");
    });

    it("rejects whitespace-only key", async () => {
      const result = await validateProviderKey({
        type: "anthropic",
        apiKey: "   ",
        label: "test",
      });
      expect(result.valid).toBe(false);
    });

    it("rejects invalid anthropic key prefix", async () => {
      const result = await validateProviderKey({
        type: "anthropic",
        apiKey: "invalid-key-123",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("sk-ant-");
    });

    it("rejects invalid openai key prefix", async () => {
      const result = await validateProviderKey({
        type: "openai",
        apiKey: "not-a-key",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("sk-");
    });

    it("rejects short google key", async () => {
      const result = await validateProviderKey({
        type: "google",
        apiKey: "short",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("too short");
    });

    it("validates correct anthropic key format with gateway check", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: { status: "ok" },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      const result = await validateProviderKey({
        type: "anthropic",
        apiKey: "sk-ant-test-key-12345",
        label: "test",
      });
      expect(result.valid).toBe(true);
    });

    it("fails when gateway unreachable", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockRejectedValue(new TypeError("fetch failed"));

      const result = await validateProviderKey({
        type: "anthropic",
        apiKey: "sk-ant-test-key-12345",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("gateway");
    });
  });

  describe("validateChannelToken", () => {
    it("rejects empty token", async () => {
      const result = await validateChannelToken({
        type: "telegram",
        botToken: "",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("required");
    });

    it("rejects invalid telegram token format", async () => {
      const result = await validateChannelToken({
        type: "telegram",
        botToken: "not-a-token",
        label: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.message).toContain("Invalid Telegram");
    });

    it("validates correct telegram token format with gateway check", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: { status: "ok" },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      const result = await validateChannelToken({
        type: "telegram",
        botToken: "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_abcdefgh",
        label: "test",
      });
      expect(result.valid).toBe(true);
    });
  });

  describe("OnboardingStore", () => {
    let store: OnboardingStore;

    beforeEach(() => {
      store = new OnboardingStore();
    });

    it("starts on provider step", () => {
      expect(store.currentStep).toBe("provider");
      expect(store.currentStepIndex).toBe(0);
    });

    it("canGoBack is false on first step", () => {
      expect(store.canGoBack).toBe(false);
    });

    it("canGoNext is false when provider not validated", () => {
      expect(store.canGoNext).toBe(false);
    });

    it("navigates forward after provider validation", () => {
      store.stepValidation = {
        ...store.stepValidation,
        provider: { valid: true, message: "ok" },
      };
      expect(store.canGoNext).toBe(true);

      store.goNext();
      expect(store.currentStep).toBe("channel");
      expect(store.currentStepIndex).toBe(1);
    });

    it("channel step is always skippable (canGoNext true)", () => {
      store.goToStep("channel");
      expect(store.canGoNext).toBe(true);
    });

    it("navigates backward", () => {
      store.goToStep("channel");
      expect(store.canGoBack).toBe(true);

      store.goBack();
      expect(store.currentStep).toBe("provider");
    });

    it("goBack does nothing on first step", () => {
      store.goBack();
      expect(store.currentStep).toBe("provider");
    });

    it("goNext does nothing on done step", () => {
      store.goToStep("done");
      expect(store.canGoNext).toBe(false);
      store.goNext();
      expect(store.currentStep).toBe("done");
    });

    it("goToStep navigates to arbitrary step", () => {
      store.goToStep("test-message");
      expect(store.currentStep).toBe("test-message");
      expect(store.currentStepIndex).toBe(2);
    });

    it("clears error on navigation", () => {
      store.error = "some error";
      store.goToStep("channel");
      expect(store.error).toBeNull();
    });

    it("complete marks onboarding done in localStorage", () => {
      store.complete();
      expect(isOnboardingComplete()).toBe(true);
      expect(store.stepValidation.done?.valid).toBe(true);
    });

    it("reset clears all state", () => {
      store.providerApiKey = "sk-ant-test";
      store.channelBotToken = "123:abc";
      store.goToStep("done");
      store.complete();

      store.reset();

      expect(store.currentStep).toBe("provider");
      expect(store.providerApiKey).toBe("");
      expect(store.channelBotToken).toBe("");
      expect(isOnboardingComplete()).toBe(false);
    });

    it("validateProvider sets loading state", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: { status: "ok" },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      store.providerType = "anthropic";
      store.providerApiKey = "sk-ant-test-key-12345";

      const promise = store.validateProvider();
      expect(store.loading).toBe(true);

      await promise;
      expect(store.loading).toBe(false);
      expect(store.stepValidation.provider?.valid).toBe(true);
    });

    it("validateProvider sets error on invalid key", async () => {
      store.providerType = "anthropic";
      store.providerApiKey = "bad-key";

      await store.validateProvider();
      expect(store.error).toBeTruthy();
      expect(store.stepValidation.provider?.valid).toBe(false);
    });

    it("validateChannel sets loading state", async () => {
      const mockGet = vi.mocked(api.GET);
      mockGet.mockResolvedValue({
        data: { status: "ok" },
        error: undefined,
        response: new Response(),
      } as ReturnType<typeof api.GET> extends Promise<infer R> ? R : never);

      store.channelBotToken = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_abcdefgh";

      const promise = store.validateChannel();
      expect(store.loading).toBe(true);

      await promise;
      expect(store.loading).toBe(false);
      expect(store.stepValidation.channel?.valid).toBe(true);
    });

    it("sendTest calls api.POST and updates state", async () => {
      const mockPost = api.POST as ReturnType<typeof vi.fn>;
      mockPost.mockResolvedValue({
        response: new Response(null, { status: 200 }),
        data: { content: "Hi!" },
        error: undefined,
      });

      store.testMessage = "Hello, Sigil!";
      await store.sendTest();

      expect(store.stepValidation["test-message"]?.valid).toBe(true);
      expect(store.testResponse).toBeTruthy();
    });

    it("sendTest sets error on failure", async () => {
      const mockPost = api.POST as ReturnType<typeof vi.fn>;
      mockPost.mockResolvedValue({
        response: new Response(null, { status: 503 }),
        data: undefined,
        error: { detail: "No provider" },
      });

      store.testMessage = "Hello";
      await store.sendTest();

      expect(store.stepValidation["test-message"]?.valid).toBe(false);
      expect(store.error).toBeTruthy();
    });

    it("isCurrentStepValid reflects validation state", () => {
      expect(store.isCurrentStepValid).toBe(false);

      store.stepValidation = {
        ...store.stepValidation,
        provider: { valid: true, message: "ok" },
      };
      expect(store.isCurrentStepValid).toBe(true);
    });
  });
});

describe("sendTestMessage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error for empty content", async () => {
    const result = await sendTestMessage("   ");
    expect(result.valid).toBe(false);
    expect(result.message).toContain("required");
  });

  it("returns success on 200 response", async () => {
    const mockPost = api.POST as ReturnType<typeof vi.fn>;
    mockPost.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: { content: "Response" },
      error: undefined,
    });

    const result = await sendTestMessage("Hello");
    expect(result.valid).toBe(true);
    expect(result.message).toContain("success");
    expect(mockPost).toHaveBeenCalledWith("/api/v1/chat/stream", {
      body: { content: "Hello" },
    });
  });

  it("returns error detail from API error response", async () => {
    const mockPost = api.POST as ReturnType<typeof vi.fn>;
    mockPost.mockResolvedValue({
      response: new Response(null, { status: 503 }),
      data: undefined,
      error: { detail: "No provider configured" },
    });

    const result = await sendTestMessage("Hello");
    expect(result.valid).toBe(false);
    expect(result.message).toContain("No provider configured");
  });

  it("returns HTTP status when error has no detail", async () => {
    const mockPost = api.POST as ReturnType<typeof vi.fn>;
    mockPost.mockResolvedValue({
      response: new Response(null, { status: 500 }),
      data: undefined,
      error: {},
    });

    const result = await sendTestMessage("Hello");
    expect(result.valid).toBe(false);
    expect(result.message).toContain("500");
  });

  it("handles network errors gracefully", async () => {
    const mockPost = api.POST as ReturnType<typeof vi.fn>;
    mockPost.mockRejectedValue(new TypeError("Failed to fetch"));

    const result = await sendTestMessage("Hello");
    expect(result.valid).toBe(false);
    expect(result.message).toBeTruthy();
  });
});

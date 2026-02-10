# Section 7: Provider System

The provider system abstracts LLM access behind a plugin interface. The agent core calls a unified API; provider plugins handle per-vendor specifics.

## Provider Interface

```protobuf
service Provider {
  rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
  rpc Chat(ChatRequest) returns (stream ChatEvent);
  rpc Status(StatusRequest) returns (StatusResponse);
}

message ChatRequest {
  string model = 1;
  repeated Message messages = 2;
  repeated ToolDefinition tools = 3;
  SystemPrompt system = 4;
  ChatOptions options = 5;
}

message ChatEvent {
  oneof event {
    TextDelta text_delta = 1;
    ToolCall tool_call = 2;
    Usage usage = 3;
    Done done = 4;
    Error error = 5;
  }
}
```

## Built-in vs Plugin Providers

```
Provider Registry
  Built-in (compiled into binary):
  +-- anthropic    (anthropic-sdk-go)
  +-- openai       (openai-go)
  +-- google       (google genai SDK)
  +-- openrouter   (OpenAI-compatible)

  Plugin providers (go-plugin):
  +-- ollama       (local models)
  +-- bedrock      (AWS)
  +-- vertex       (GCP)
  +-- custom       (any OpenAI-compatible API)
```

Built-in providers are compiled into the gateway binary for zero-config common cases.

## Model Routing and Failover

```yaml
providers:
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
  openai:
    api_key: "${OPENAI_API_KEY}"
  ollama:
    endpoint: "http://localhost:11434"

models:
  default: "anthropic/claude-sonnet-4-5"

  # Workspace overrides
  overrides:
    homelab: "anthropic/claude-opus-4-6"
    family: "openai/gpt-4.1-mini"

  # Failover chain
  failover:
    - "anthropic/claude-sonnet-4-5"
    - "openai/gpt-4.1"
    - "ollama/llama3:70b"

  # Cost controls
  budgets:
    per_session_tokens: 100000
    per_hour_usd: 5.00
    per_day_usd: 50.00
```

### Routing Logic

```
Agent needs LLM call
  +-- Check workspace model override -> use if set
  +-- Otherwise use default model
  +-- Check budget -> DENY if exceeded (notify user)
  +-- Call provider.Chat()
  |   +-- Success -> stream response to agent loop
  |   +-- Rate limited -> try next in failover chain
  |   +-- Auth error -> try next in failover chain
  |   +-- Provider down -> try next in failover chain
  +-- All providers exhausted -> error to user
```

## Provider Capabilities

```protobuf
message ModelCapabilities {
  bool supports_tools = 1;
  bool supports_vision = 2;
  bool supports_streaming = 3;
  bool supports_thinking = 4;
  int32 max_context_tokens = 5;
  int32 max_output_tokens = 6;
}
```

The agent core adapts based on capabilities: skip images for non-vision models, disable tool use where unsupported, manage context window with compaction.

# Guides

Practical guides for configuring and using Sigil effectively.

## Channel Setup

How to connect messaging platforms to your Sigil instance.

### Telegram Channel

Configure Telegram bot integration for agent interactions.

### Discord Channel

Set up Discord bot and server integration.

### WhatsApp Channel

Connect WhatsApp Business API for messaging.

### Custom Channel Plugins

Create your own channel plugin for other platforms.

## Workspace Configuration

Managing workspaces for isolated agent contexts.

### Creating Workspaces

Set up new workspaces with custom configurations.

### Workspace Scoping

Understanding how workspaces isolate data and settings.

### Sharing Workspaces

Collaborate across workspaces on remote nodes.

## Provider Configuration

Configuring LLM providers for your agents.

### Anthropic Provider

Set up Claude models with API key and budget controls.

### OpenAI Provider

Configure GPT models and streaming settings.

### Google Provider

Integrate Gemini models into your agent workflows.

### Custom Providers

Implement custom LLM provider plugins.

## Skill Creation

Build custom skills to structure agent workflows.

### Writing Skill Manifests

Define skill metadata, capabilities, and parameters.

### Implementing Skill Logic

Create skill handlers with structured inputs and outputs.

### Testing Skills

Validate skill behavior with unit and integration tests.

## Memory Management

Configure tiered memory for agent context and retrieval.

### Full-Text Search

Use FTS5 for fast message and context search.

### Vector Search

Leverage sqlite-vec for semantic similarity search.

### Memory Summaries

Implement summarization strategies for long-running sessions.

## Security Configuration

Set up capability-based access control and sandboxing.

### Capability Grants

Define granular permissions for plugins.

### Execution Tiers

Choose isolation levels: Wasm, Process, or Container.

### Audit Logging

Track security-relevant operations.

## Node Management

Configure remote node access and synchronization.

### Tailscale Integration

Set up secure node-to-node communication.

### Node Registration

Add and authenticate remote nodes.

### Workspace Sync

Synchronize workspace state across nodes.

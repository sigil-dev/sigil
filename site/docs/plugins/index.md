# Plugin Development

Learn how to build, test, and distribute Sigil plugins.

## Plugin System Overview

Understanding Sigil's HashiCorp-style plugin architecture.

### Plugin Types

Four plugin types: Provider, Channel, Tool, and Skill.

### Execution Tiers

Three isolation levels: Wasm (Wazero), Process (go-plugin), Container (OCI).

### Plugin Lifecycle

Initialization, capability checking, execution, and shutdown.

## Creating a Plugin

Step-by-step guide to building your first plugin.

### Scaffolding

Use the `/sigil-new-plugin` Claude Code command to scaffold a new plugin with
manifest, code, and tests. Alternatively, create the plugin directory structure
manually following the patterns in `plugins/`.

### Manifest File

Define plugin metadata, type, capabilities, and execution tier.

### Plugin Interface

Implement the gRPC service contract for your plugin type.

### Registering the Plugin

Add your plugin to the registry for discovery.

## Manifest Reference

Complete specification for plugin manifest files.

### Metadata Fields

Name, version, author, description, license.

### Capability Requirements

Declare required capabilities using glob patterns.

### Execution Configuration

Specify execution tier, sandbox settings, and resource limits.

### Plugin Dependencies

Declare dependencies on other plugins or system libraries.

## Tool Plugins

Build tool plugins to extend agent capabilities.

### Tool Interface

Implement the `Tool` gRPC service for custom actions.

### Input Validation

Validate and sanitize tool inputs from LLM outputs.

### Output Formatting

Structure tool results for agent consumption.

### Error Handling

Return structured errors for agent loop recovery.

## Channel Plugins

Create channel plugins for messaging platforms.

### Channel Interface

Implement the `Channel` gRPC service for message routing.

### Message Handlers

Process incoming messages and route to agents.

### Event Streaming

Stream agent responses back to the platform.

### Authentication

Handle platform-specific authentication flows.

## Provider Plugins

Integrate custom LLM providers.

### Provider Interface

Implement the `Provider` gRPC service for LLM calls.

### Request Mapping

Transform Sigil requests to provider-specific formats.

### Streaming Responses

Support server-sent events for real-time agent output.

### Budget Tracking

Track token usage and enforce limits.

## Skill Plugins

Build structured workflows as skill plugins.

### Skill Interface

Implement the `Skill` gRPC service for workflow execution.

### Parameter Schemas

Define structured input schemas using JSON Schema.

### Workflow Steps

Chain multiple tool calls into cohesive workflows.

### State Management

Maintain skill state across execution steps.

## Sandboxing and Security

Configure plugin isolation and capability enforcement.

### Wasm Plugins

Memory-safe plugins with no syscall access.

### Process Sandboxing

OS-level isolation with bwrap (Linux) or sandbox-exec (macOS).

### Container Plugins

Full container isolation for untrusted or network-heavy plugins.

### Capability Gates

Enforce capability checks before plugin operations.

## Testing Plugins

Validate plugin behavior with comprehensive tests.

### Unit Testing

Test plugin logic in isolation with mocks.

### Integration Testing

Test plugin interaction with Sigil core.

### Security Testing

Verify capability enforcement and sandbox behavior.

## Distribution

Package and distribute plugins for others to use.

### Plugin Packaging

Bundle plugin binaries, manifests, and dependencies.

### Plugin Registry

Publish plugins to the community registry.

### Versioning

Manage plugin versions and compatibility.

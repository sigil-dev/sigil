# Getting Started

Welcome to Sigil! This guide will help you install, configure, and run Sigil for the first time.

## Prerequisites

Requirements for running Sigil on your system.

- Go 1.25 or later
- CGo-enabled environment (required for SQLite)
- Supported operating systems: Linux, macOS, Windows (with WSL)

## Installation

How to install Sigil on your system.

### Binary Installation

Download pre-built binaries from the releases page.

### Building from Source

Clone the repository and build using the Task runner:

```bash
git clone https://github.com/sigil-dev/sigil.git
cd sigil
task build
```

## First Run

Start Sigil for the first time and complete initial configuration.

### Initialize Configuration

Generate the default configuration file:

```bash
sigil init
```

### Start the Server

Launch Sigil in development mode:

```bash
sigil start
```

## Quick Start Tutorial

A step-by-step tutorial to create your first AI agent interaction.

### Create a Workspace

Workspaces isolate agent contexts and data.

### Configure a Provider

Set up an LLM provider (Anthropic, OpenAI, or Google).

### Set Up a Channel

Connect a messaging platform to interact with your agent.

### Send Your First Message

Interact with your agent through the configured channel.

## Next Steps

- Explore the [Guides](../guides/) for detailed configuration options
- Learn about [Security](../security/) and capability management
- Review [Plugin Development](../plugins/) to extend Sigil

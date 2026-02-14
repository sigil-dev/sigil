# Operators Guide

Operational guidance for deploying and managing Sigil in production.

## Deployment

How to deploy Sigil to production environments.

### System Requirements

Hardware and software prerequisites for running Sigil.

### Configuration

Production configuration best practices and environment variable overrides.

### Networking Modes

Sigil supports `local` and `tailscale` networking modes via the `networking.mode`
configuration key.

## Monitoring

Observability and health checking for Sigil deployments.

### Health Checks

Use `sigil doctor` or the `/health` endpoint to verify server health.

### Structured Logging

Sigil uses `slog` for structured logging. Configure verbosity with the
`--verbose` flag or by setting log levels in your deployment tooling.

### Metrics

Guidance on collecting and exporting operational metrics.

## Backup and Restore

Protecting your Sigil data.

### SQLite Databases

Each workspace uses a separate SQLite database. Back up the data directory
(configured via `--data-dir` or `storage.backend` settings) to preserve all
workspace state.

### Configuration Files

Keep configuration files under version control or in a secrets manager.

## Scaling

Considerations for scaling Sigil beyond a single instance.

### Single-Node Performance

Tuning tips for single-node deployments.

### Multi-Node with Tailscale

Using Sigil's Tailscale integration (`networking.mode: tailscale`) to distribute
workloads across remote nodes.

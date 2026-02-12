# Section 4: Channel System

Channels are plugins with unique concerns: authentication with external platforms, user identity/pairing, message routing, and presence.

## Channel Plugin Contract

Every channel plugin implements the `Channel` gRPC service:

- **Init(config):** Authenticates with platform (bot token, etc.), reports supported features, returns error if auth fails.
- **Start() -> stream InboundMessage:** Long-lived stream of incoming messages. Each carries sender identity, channel ID, content (text/media/reaction), thread context. Plugin handles reconnection internally.
- **Send(OutboundMessage) -> SendResponse:** Gateway calls this to deliver agent responses. Supports text, media, reactions, typing indicators. Returns delivery status + platform message ID.
- **GetIdentity(platformUserId) -> UserIdentity:** Resolves platform-specific user to a canonical ID for pairing and access control.

## Channel Auth and Pairing

Users MUST be approved before the agent responds (configurable):

```text
Message arrives
  |
  v
Identity Resolution (channel plugin -> canonical UserIdentity)
  |
  v
Pairing Check (against pairing DB)
  |
  +-- paired  -> Route to agent
  +-- pending -> Queue for owner approval
  +-- denied  -> Drop (silent or with message)
```

### Pairing Modes (configurable per-channel)

| Mode | Behavior |
|------|----------|
| `open` | Anyone can talk to the agent (public bots) |
| `allowlist` | Only pre-approved users (by platform ID or pattern) |
| `pair_on_request` | Unknown users get a "request sent" message, owner approves via UI/CLI |
| `pair_with_code` | User must provide a one-time code (generated in UI) to pair |
| `closed` | Only owner, no pairing possible |

## Secrets Handling

Channel plugins need platform credentials (bot tokens, API keys):

```yaml
plugins:
  telegram-channel:
    config:
      bot_token: "${TELEGRAM_BOT_TOKEN}"         # env var reference
      # OR
      bot_token: "vault:secret/telegram#token"   # future: vault integration
```

- Secrets marked `secret: true` in the plugin's config schema are encrypted at rest
- Never logged (redacted in audit logs)
- Passed to plugin via gRPC `Init` -- never written to plugin's filesystem
- Plugin process cannot read the gateway's environment (sandbox enforced)

## Multi-Channel Identity Routing

A user might talk to the agent on Telegram and WhatsApp. The gateway understands that `@alice` on Telegram and `+1555123456` on WhatsApp are the same person:

```yaml
users:
  - id: "usr_abc123"
    name: "Alice"
    role: owner
    identities:
      - channel: telegram
        platform_id: "alice"
      - channel: whatsapp
        platform_id: "+15551234567"
      - channel: discord
        platform_id: "alice#1234"
    session_mode: unified     # unified | per_channel
```

- **`unified` mode:** Same session across all channels. Start on Telegram, continue on WhatsApp.
- **`per_channel` mode:** Separate sessions per channel for compartmentalization.

Identity resolution is a core gateway concept, not a plugin concern.

## Channel Feature Negotiation

Not all channels support the same features:

```protobuf
message ChannelCapabilities {
  bool supports_media = 1;
  bool supports_reactions = 2;
  bool supports_threads = 3;
  bool supports_editing = 4;
  bool supports_typing = 5;
  bool supports_voice = 6;
  bool supports_rich_text = 7;
  int32 max_message_length = 8;
  repeated string media_types = 9;
}
```

The agent core uses this to adapt responses -- strip markdown for channels that do not support it, use reactions for acknowledgment where available, chunk long messages for platforms with character limits.

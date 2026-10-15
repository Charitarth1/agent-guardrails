# Hardening a personal OpenClaw host

`openclaw.hardened.example.json` is the configuration I run for always-on agents reachable from Telegram, with identifiers and paths replaced by placeholders. An agent you can message from your phone is an agent anyone who gets into that chat can steer, so the defaults here assume the chat is hostile.

## What each setting does

| Setting | Value | Why |
|---|---|---|
| `agents.defaults.sandbox.mode` | `all` | Every session runs in a container, not on the host. |
| `sandbox.backend` | `podman` | Daemonless containers; run Podman rootless for a smaller host footprint. |
| `sandbox.docker.network` | `none` | The sandbox has no network. Fetching goes through the gateway's own `web_fetch` tool, where it can be bounded and logged. |
| `readOnlyRoot`, `capDrop: ["ALL"]`, `user: 1000:1000` | | Read-only filesystem, no Linux capabilities, not root. |
| `memory`, `memorySwap`, `pidsLimit` | 256–768 MB, 128 | A runaway agent can't starve the host. Set per agent. |
| `binds` | `…:/sources:ro` | The only host data an agent sees is a read-only sources folder. |
| `dangerouslyAllowContainerNamespaceJoin` / `ReservedContainerTargets` | `false` | No joining other containers' namespaces. |
| `prune.idleHours` / `maxAgeDays` | `1` / `1` | Sandboxes don't accumulate state between sessions. |
| `tools.fs.workspaceOnly` | `true` | File tools can't leave the agent's workspace. |
| `tools.elevated.enabled` | `false` | No privileged tool calls. |
| `tools.exec.strictInlineEval` | `true` | Stricter handling of inline interpreter code (`python -c`, `node -e`). Check your OpenClaw version's docs for the exact semantics. |
| `tools.deny` | `browser`, `x_search` | Smallest useful tool surface. |
| `commands.bash` / `config` / `mcp` / `plugins` | `false` | Chat can't run shell commands, edit config, or add MCP servers or plugins. |
| `channels.telegram.dmPolicy` | `allowlist` | Only allowlisted user IDs can talk to the bots. |
| `groupPolicy` | `disabled` | Bots can't be added to groups, where anyone could message them. |
| `configWrites` | `false` | The channel can't change its own config. |
| `gateway.bind` | `loopback` | The gateway isn't reachable from the network. Reach the host over a VPN such as Tailscale. |
| `gateway.auth.token` | secret-store reference | Never a literal in the config file. |
| `modelPolicy.allow` | explicit list | Agents can only use models you've approved. |
| `diagnostics.otel` | enabled | Traces, metrics and logs go to your own collector so incidents can be reconstructed. |

## The lesson that matters most

**A tool policy is only as strong as the exec tool.** Denying `browser` or setting `workspaceOnly` means nothing if the agent can still run `cat` or `curl` through a shell. In my own setup, exec was not denied at first, which quietly bypassed every other control. See [F-5 in the self-audit](../docs/lessons-from-a-self-audit.md).

## Config as code

`openclaw-config.sh` keeps the live config in version control without leaking it:

```sh
./openclaw-config.sh status    # drift check
./openclaw-config.sh diff      # what changed
./openclaw-config.sh export    # live -> tracked, after a secret scan and identifier redaction
./openclaw-config.sh restore   # tracked -> live, backs up first
```

Export fails closed. It refuses if any value looks like a credential (including Telegram bot tokens), if the gateway token is a literal, or if any identifier survives redaction. Identifiers live in `identifiers.local` (gitignored, mode 0600):

```
TELEGRAM_OWNER_ID=<numeric id>
```

Tests: `sh test_openclaw_config.sh` (needs `jq`).

## Known gaps

- Bot tokens referenced by `tokenFile` are plaintext files on disk. Keep them mode 0600, outside any synced folder, or move them into the secret store.
- The OTel exporter can include message content in logs. Point it at a collector you control, over an encrypted link.

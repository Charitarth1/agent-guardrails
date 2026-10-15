# Threat model

## What I'm protecting

- **Credentials:** API keys, bot tokens, SSH and cloud credentials, and session tokens.
- **Private data:** personal finance, health and identity documents, client material, and private notes.
- **My name:** anything published, pushed or sent as me.

## Who or what the threat is

1. **Injected instructions** in content an agent reads: web pages, RSS, emails, chat messages, documents, third-party skills.
2. **Agent mistakes:** a well-meaning agent pasting a key into a file, reading a folder it shouldn't, or pushing to the wrong remote.
3. **Supply chain:** a skill, plugin or MCP server that does more than it says.
4. **Someone reaching the chat channel** of an always-on agent.

I don't defend against an attacker who already has my user account or root on the host. At that point these controls are speed bumps.

## Rule of Two

No component holds more than two of these:

| | Untrusted input | Sensitive data or credentials | External side effects |
|---|:---:|:---:|:---:|
| Research or fetch agent | yes | no | no |
| Drafting or prep agent | yes | yes | no (drafts on a branch only) |
| Publisher or merge step | no (human-cleared artifacts only) | yes | yes |

The step that holds side effects only accepts artifacts a human has cleared, which is where the human in the loop sits.

## Controls by layer

| Layer | Control | In this repo |
|---|---|---|
| Harness permissions | deny reads of private folders and credential files; ask before push, curl, rm, publish | `claude-code/settings.example.json` |
| Pre-execution hook | DLP on content, paths and commands; fails closed | `claude-code/hooks/dlp_pre_tool_use.py` |
| Post-execution hook | append-only audit record of every tool call | `claude-code/hooks/audit_post_tool_use.py` |
| Supply chain | offline static scan before installing skills | `skill-scanner/` |
| Host isolation | containers with no network, read-only root, no capabilities; loopback-only gateway; chat allowlist | `openclaw/openclaw.hardened.example.json` |
| Config integrity | tracked config, drift detection, secret-scanned and redacted exports | `openclaw/openclaw-config.sh` |
| Human checkpoint | approve and merge only at the terminal, never from chat | described in `docs/lessons-from-a-self-audit.md` |

What gets past each layer: [limitations.md](limitations.md).

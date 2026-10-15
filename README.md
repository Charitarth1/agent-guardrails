# agent-guardrails

Guardrails I use to run AI agents on my own machines without handing them the keys: a data-loss-prevention hook for Claude Code, an offline scanner for third-party agent skills, and a hardened OpenClaw host config. All three run on my own setup and were shaped by an adversarial audit of it. The hook and the config tooling have test suites.

I work in AI governance. This repo is the practical side of that work: what it takes to apply "human in the loop" and "least privilege" to agents I actually run.

## What's here

| Folder | What it does | Status |
|---|---|---|
| [`claude-code/`](claude-code/) | PreToolUse DLP hook (blocks secrets, card and SIN numbers, client names, private paths, exfiltration commands) and a PostToolUse audit hook | 44-case regression suite plus structural tests, all passing |
| [`skill-scanner/`](skill-scanner/) | Offline supply-chain scan of third-party skills, plugins and MCP servers, wrapping Cisco's and NVIDIA's open-source scanners at pinned versions | Used to vet an 800+ skill library |
| [`openclaw/`](openclaw/) | Hardened config for an always-on, chat-reachable agent host, plus config-as-code with secret scanning and identifier redaction | Tested with synthetic configs |
| [`docs/`](docs/) | [Lessons from a self-audit](docs/lessons-from-a-self-audit.md), the [threat model](docs/threat-model.md) and [known limitations](docs/limitations.md) | |

## The ideas behind it

**Rule of Two.** No single agent session should hold all three of: untrusted input, sensitive data or credentials, and the ability to act externally (publish, push, send). Any two are manageable. All three make a prompt-injection exfiltration path.

**Deterministic controls first.** Use a regex, a hash or a kernel sandbox wherever possible. Models are good at judgment and bad at being a security boundary.

**Test both errors.** Every "must block" case has "must allow" neighbours. A guardrail that blocks real work gets switched off, and then it protects nothing.

**Fail closed.** A crash in a guard blocks. An unreadable config warns loudly. A partial redaction refuses to write.

## Quick start (Claude Code DLP hook)

```bash
git clone https://github.com/<you>/agent-guardrails.git
cd agent-guardrails/claude-code/hooks
cp guardrails.example.json guardrails.json        # list your private folders
printf 'acme corp\n' > dlp_denylist.local.txt     # client names, codenames
python3 ../tests/test_dlp_patterns.py             # should print ALL PASSED
```

Then merge `claude-code/settings.example.json` into your `.claude/settings.json`, using absolute paths to the hooks. Both `guardrails.json` and `*.local.txt` are gitignored.

Requirements: Python 3.9+ (stdlib only). The OpenClaw tests need `jq`, and the skill scanner needs `uv`.

## Read this before relying on it

The DLP hook is a tripwire, not a sandbox. [docs/limitations.md](docs/limitations.md) lists what gets past it. Use it alongside harness permissions and OS-level isolation.

## License

MIT. See [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).

---

Built by [Charitarth Bharti](https://safeaiguy.com/), who works on AI governance and agentic AI risk.

# agent-guardrails

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Python%203.9%2B%20Stdlib-green.svg)](guardrails.py)
[![CI](https://github.com/Charitarth1/agent-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/Charitarth1/agent-guardrails/actions/workflows/ci.yml)
[![Architecture: Dual-Engine](https://img.shields.io/badge/Architecture-Dual--Engine%20(Brain%20%2B%20Brakes)-purple.svg)](#the-dual-engine-architecture)

> **Enterprise AI Agent Guardrails Toolkit: Governance-as-Code for Autonomous Coding & Tool-Calling Agents.**  
> Zero external pip dependencies. Apache 2.0. Built for Claude Code, Cursor, Antigravity, OpenHands, and custom agent harnesses.  
> Created by Charitarth Bharti ([safeaiguy.com](https://safeaiguy.com)).

Guardrails built from first principles and refined through adversarial self-audits to run AI agents safely on developer machines and CI/CD pipelines without handing them the keys.

---

## Security Model: Tripwire, Not a Sandbox

> [!WARNING]
> **Pattern-based hooks are tripwires, not security boundaries.**
> A deterministic regex filter or PreToolUse hook running as the same OS user as the agent cannot withstand an active, malicious adversary who has arbitrary shell execution capabilities. If the agent can execute arbitrary Python or shell commands, it can inspect its own environment, read local files, or kill unprivileged parent processes.
> 
> True security confinement requires **operating-system level isolation**: running the agent in a rootless container (Docker/Podman), an isolated VM (Firecracker/gVisor), or a dedicated unprivileged user account without access to host secrets or network interfaces.
> 
> `agent-guardrails` is designed as a **tripwire against accidental mutations, naive prompt injections, and inadvertent data leakage**, and as a structured governance framework for enterprise compliance (NIST AI RMF, ISO/IEC 42001, GovTech ARC). Read [docs/limitations.md](docs/limitations.md) before deploying in untrusted environments.

---

## The Dual-Engine Architecture

A robust agent governance architecture cannot rely solely on prompt engineering (which fails under indirect injection) nor purely on external network firewalls (which cannot inspect tool semantics). This toolkit implements the **Dual-Engine Model**:

```
┌──────────────────────────────────────────────────────────┐
│             THE DUAL-ENGINE GOVERNANCE SYSTEM            │
└──────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌──────────────────┐               ┌──────────────────┐
│    THE BRAIN     │               │    THE BRAKES    │
│ (In-Context)     │               │ (Deterministic)  │
├──────────────────┤               ├──────────────────┤
│ Downloadable     │               │ PreToolUse Hook  │
│ Agent Skills     │               │ Runtime Engine   │
│ (`skills/`)      │               │ (`src/`)         │
├──────────────────┤               ├──────────────────┤
│ • Blast-Radius   │               │ • 4-Tier DLP     │
│   Calculation    │               │ • Nonce Fencing  │
│ • Safe TDD Gates │               │ • Out-of-Band    │
│ • Proactive      │               │   HMAC Gate      │
│   Self-Auditing  │               │ • SHA-256 Chain  │
└──────────────────┘               └──────────────────┘
```

1. **The Brain (In-Context Guidance - `skills/`):**
   - Downloadable agent skill packages conforming to modern `SKILL.md` specifications.
   - Teaches agents self-governance: blast radius surface triage, safe mutation tiers, mandatory TDD verification before claiming bugfixes, and terminal clearance workflows.
   - Single-command vendoring directly into your favorite agent harness:
     ```bash
     guardrails vendor-skills --target claude-code   # installs to .claude/skills/
     guardrails vendor-skills --target cursor        # installs to .cursor/rules/
     guardrails vendor-skills --target antigravity   # installs to .gemini/antigravity/skills/
     ```

2. **The Brakes (Deterministic Runtime Firewalls - `src/`):**
   - Hard, fail-closed enforcement at the tool-call boundary (Exit Code 2 = BLOCK; 0 = ALLOW).
   - Operates before terminal execution or API calls occur.
   - Operates independently of model context; does not rely on model self-policing.

---

## Core Capabilities

| Capability | Module | What it does |
|:---|:---|:---|
| **4-Tier DLP Firewall** | [`src/dlp_pre_tool_use.py`](src/dlp_pre_tool_use.py) | Inspects tool payloads across GLOBAL, PATH, COMMAND, and OUTBOUND tiers. Defangs shell quoting obfuscation (F-16) and verifies Luhn checksums on cards/SINs. |
| **Out-of-Band HMAC Gate** | [`src/approval_gate.py`](src/approval_gate.py) | Holds `git push` and `git remote add` until a human mints a single-use, HMAC-signed receipt from an interactive terminal (F-0, F-3). Destructive commands (`terraform destroy`, `DROP TABLE`, force-push) are hard blocks with no approval path. An agent running as your OS user can still mint a receipt; see [limitations](docs/limitations.md). |
| **Cryptographic Input Fencing** | [`src/fence_untrusted.py`](src/fence_untrusted.py) | Wraps untrusted external content in cryptographically random 8-byte (16 hex character) nonces to neutralize Indirect Prompt Injections (F-2) and defangs markdown image exfiltration. |
| **Audit Hash Ledger** | [`src/audit_post_tool_use.py`](src/audit_post_tool_use.py) | Records tool invocations into an append-only JSONL log chained with SHA-256 hashes without leaking sensitive payload data; detects naive tampering by convention (see limitations.md). |
| **Pluggable Policy Packs** | [`packs/`](packs/) | Modular governance packs: `core-secrets`, `destructive-infra`, `supply-chain-coding`, `pii-regulated`, and `personal-privacy`. |
| **18-Risk Control Matrix** | [`matrix/`](matrix/) | Independent risk-control matrix mapping 18 agentic risks across 6 domains (AG-DAT, AG-SEC, AG-SAF, AG-REL, AG-ACC, AG-MIS) mapped to GovTech ARC, OWASP Agentic Top 10, MIT AI Risk Repository and NIST AI RMF (IDs checked against each source). |
| **Root CLI Orchestrator** | [`guardrails.py`](guardrails.py) | Single zero-dependency CLI providing `init`, `check`, `fence`, `approve`, `verify-log`, `vendor-skills`, `install-hooks`, and `compliance-export`. |
| **Backward-Compatible Hooks** | [`claude-code/`](claude-code/) | PreToolUse and PostToolUse hook wrappers for existing Claude Code configurations with 44-case regression suite. |

---

## Quick Start: The `guardrails` CLI

The entire toolkit runs with **pure Python 3.9+ standard library** (no `pip install` required):

```bash
# 1. Clone the repository
git clone https://github.com/Charitarth1/agent-guardrails.git
cd agent-guardrails

# 2. In YOUR project: create ./guardrails.json, then wire the hooks into
#    ./.claude/settings.json and a managed block in ./AGENTS.md (existing content is kept)
cd /path/to/your-project
python3 /path/to/agent-guardrails/guardrails.py init
python3 /path/to/agent-guardrails/guardrails.py install-hooks
#    The hook pins this guardrails.json and a hash of it plus the active packs.
#    After editing either, re-run install-hooks, or every tool call fails closed.

# 3. Vendor the optional agent skills (guidance, not enforcement)
python3 /path/to/agent-guardrails/guardrails.py vendor-skills --target claude-code

# 4. Restart Claude Code so it loads the new hooks

# 5. Check a payload against the active policies (uses ./guardrails.json)
python3 /path/to/agent-guardrails/guardrails.py check --tool Bash --payload "terraform destroy -auto-approve"
# Output: BLOCKED: rule='terraform_destroy', tier='command' (Exit code 2)

# 6. Approve one push, from your own terminal (not through the agent)
python3 /path/to/agent-guardrails/guardrails.py approve --scope git_remote_push --ttl 15

# 7. Check the audit log's hash chain (detects naive edits only)
python3 /path/to/agent-guardrails/guardrails.py verify-log --log tool_audit.jsonl

# 8. Run the comprehensive test suite
./guardrails.py test
```

---

## Pluggable Policy Packs (`packs/`)

Policies are modular, versioned JSON definitions located in `packs/`:

- **`core-secrets.json`**: High-confidence interception of API keys (GitHub, Anthropic, OpenAI, AWS, Stripe), private keys, SSH files, and system keychains.
- **`destructive-infra.json`**: Prevents unvetted infrastructure destruction (`terraform destroy`, `kubectl delete ns`), database table drops, and force pushes.
- **`supply-chain-coding.json`**: Intercepts download-and-execute pipes (`curl | sh`), base64 decoding into shells, inline interpreter evaluation (`python -c`), and reverse shells.
- **`pii-regulated.json`**: Intercepts US SSNs, Canadian SINs, and Luhn-valid credit card numbers; prevents outbound leakage of financial routing info.
- **`personal-privacy.json`**: Blocks outbound publishing of personal retirement accounts (TFSA, RRSP), dating app profiles, and residential lease agreements.

To customize active packs, edit `guardrails.json`:
```json
{
  "active_packs": [
    "core-secrets",
    "destructive-infra",
    "supply-chain-coding",
    "pii-regulated",
    "personal-privacy"
  ]
}
```

---

## Downloadable Agent Skills (`skills/`)

- **[`safe-agent-coder`](skills/safe-agent-coder/SKILL.md)**: Teaches agents blast-radius triage (Tier 1 Read, Tier 2 Bounded Mutation, Tier 3 Terminal Clearance), safe dependency handling, and non-negotiable TDD gates.
- **[`untrusted-data-guard`](skills/untrusted-data-guard/SKILL.md)**: Teaches agents cryptographic input fencing, indirect prompt injection defense, and the Rule-of-Two separation.
- **[`governance-auditor`](skills/governance-auditor/SKILL.md)**: Step-by-step instructions for agents to self-audit harness configurations and verify the 18 controls in `risk_control_matrix.json`.

---

## Scope: What a Tool-Call Hook Can Decide

The MIT AI Risk Repository defines 24 risk subdomains. It does not say which ones a runtime hook can decide; [our classification](docs/agentic_risk_screener.md#2-our-classification-of-the-mit-ai-risk-repository-24-subdomains) does, row by row:

- **Decidable at the tool-call boundary (5):** 2.1 privacy and sensitive-data leakage, 2.2 AI system security attacks, 5.2 loss of human agency (approval of irreversible actions), 7.3 lack of robustness (an agent's destructive mistakes), 7.4 lack of transparency (per-call audit records).
- **Decidable in part (3):** 4.2 cyberattacks (shell and tunnel commands only), 7.2 dangerous capabilities (only the tools an agent is given), 7.6 multi-agent risks (static configuration lint only).
- **Not decidable here (16):** including bias, toxicity, misinformation, fraud, overreliance, socioeconomic and environmental harms. A hook should never be sold as addressing these.

Read the full methodology in [docs/agentic_risk_screener.md](docs/agentic_risk_screener.md) and review the compiled matrix in [matrix/MATRIX.md](matrix/MATRIX.md).

---

## Historical Lessons & Self-Audit Findings

The architecture of this repository was directly shaped by real-world red-teaming and self-auditing of autonomous agent setups:

- **[Lessons from a Self-Audit](docs/lessons-from-a-self-audit.md)**: Details the 17 critical findings (F-0 through F-16), including how flat Claude Code settings schemas silently disable hooks (F-1), how timestamp `NaN` parsing can bypass approval gates (F-3), and how shell quoting bypasses naive path matching (F-16).
- **[Threat Model](docs/threat-model.md)**: The adversarial assumptions governing agent tool execution.
- **[Known Limitations](docs/limitations.md)**: Honest boundaries of regex and pattern-based tripwires.

---

## Verification & Testing

This project enforces strict Test-Driven Development (TDD). Every blocking rule is paired with adjacent `MUST_ALLOW` tests to prevent false-positive productivity friction:

```bash
# Run the root test suite (all modules; CI runs this on every push)
./guardrails.py test

# Run legacy Claude Code regression suite
python3 claude-code/tests/test_dlp_patterns.py
```

---

## License & Attribution

- **License:** Apache License 2.0. Free for open-source and enterprise adoption. See [LICENSE](LICENSE).
- **Attribution Notice:** See [NOTICE](NOTICE) for acknowledgments to GovTech Singapore (ARC), MIT FutureTech, MITRE ATLAS, and roboticforce.

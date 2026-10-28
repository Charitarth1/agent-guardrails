# Enterprise Agentic Risk Screener & Control Methodology

> A practitioner's guide to runtime safety, deterministic enforcement boundaries, and our operational classification of the MIT AI Risk Repository's 24 subdomains (5 decidable at the tool-call boundary, 3 in part).

---

## Executive Summary

Enterprise adoption of autonomous coding agents and agentic workflows (Claude Code, Cursor, Antigravity, OpenHands, custom LangGraph harnesses) introduces operational risks that traditional web application firewalls and static code analyzers cannot mitigate. Because autonomous agents generate code, execute terminal commands, ingest untrusted web context, and invoke external APIs, governance must operate at the **runtime tool execution boundary**.

This screener establishes an engineering-first, legally unencumbered methodology derived from first principles, aligned with GovTech Singapore's **Agentic Risk & Capability Framework (ARC)**, MITRE ATLAS, NIST AI RMF 1.0, ISO/IEC 42001, and our operational classification of the MIT AI Risk Repository.

---

## 1. The Dual-Engine Governance Model

A common failure mode in AI governance is treating safety as either purely prompt-based or purely external:

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

1. **The Brain (In-Context Skills):**
   - Autonomous models reason, plan, and calculate blast radius.
   - Without guidance, agents attempt large unvetted multi-file mutations or fail to run automated test gates before claiming success.
   - The skills in `skills/` (`safe-agent-coder`, `untrusted-data-guard`, `governance-auditor`) guide the model's operational planning and self-discipline.
2. **The Brakes (Deterministic Runtime Firewalls):**
   - In-context instructions **fail** when subjected to Indirect Prompt Injections (IPI) or adversarial prompt manipulations. Prompting is guidance, not a security perimeter.
   - Deterministic PreToolUse hooks in `src/` intercept tool invocation payloads *before* the operating system or API executes them.
   - If a payload matches a blocked pattern or lacks an out-of-band terminal HMAC receipt, execution is terminated immediately with exit code `2`.

---

## 2. Our Classification of the MIT AI Risk Repository (24 Subdomains)

The MIT AI Risk Repository (Slattery et al., *A meta-review, database, and taxonomy of risks from artificial intelligence*, v3, March 2026) sorts 1,700+ documented risks from 74 frameworks into 7 domains and 24 subdomains. Subdomain numbers and names below are copied from that paper. **The repository does not classify subdomains by runtime decidability. This table is our operational classification, not MIT's.**

"Decidable at the tool-call boundary" means a deterministic check on a single tool call (its name, arguments and target paths) can intercept at least some instances of the risk before the action happens. "Implemented here" says what this repository actually ships for it; "Nothing" means exactly that.

| Subdomain | Name (MIT AI Risk Repository v3) | Decidable at the tool-call boundary? | Implemented here | Rationale |
|:---|:---|:---:|:---|:---|
| 1.1 | Unfair discrimination and misrepresentation | No | Nothing | Depends on model behaviour and outcomes across many decisions, not on one tool call. |
| 1.2 | Exposure to toxic content | No | Nothing | Judging toxicity needs a classifier and context; a regex on tool arguments is not a reliable decision. |
| 1.3 | Unequal performance across groups | No | Nothing | A model-evaluation property. |
| 2.1 | Compromise of privacy by obtaining, leaking, or correctly inferring sensitive information | **Yes** | GLOBAL tier secret and PII patterns (Luhn-checked cards and SINs, SSNs), PATH tier denylisted folders, OUTBOUND tier personal-data terms | A tool call that writes, sends or reads a known secret or protected path can be stopped before it runs. Inference of private facts is not covered. |
| 2.2 | AI system security vulnerabilities and attacks | **Yes** | Nonce fencing and image defanging for untrusted input, COMMAND tier blocks on interpreter evasion, reverse shells and tunnels, self-protection of guardrails files with a pinned policy digest | The attack surface here is the agent's own tool use. Regex matching is a tripwire, not a sandbox (see limitations.md). |
| 3.1 | False or misleading information | No | Nothing | Factual accuracy is not visible in a tool call. |
| 3.2 | Pollution of information ecosystem and loss of consensus reality | No | Nothing | A population-level effect. |
| 4.1 | Disinformation, surveillance, and influence at scale | No | Nothing | Intent and scale are not visible in one call. |
| 4.2 | Cyberattacks, weapon development or use, and mass harm | Partly | Nothing beyond the 2.2 controls | Some cyber-offence actions (reverse shells, tunnels) are recognisable per call, and this repo blocks them under 2.2. Weapon development is not decidable here. |
| 4.3 | Fraud, scams, and targeted manipulation | No | Nothing | Requires intent and recipient context. |
| 5.1 | Overreliance and unsafe use | No | Nothing | A property of how people use the system. |
| 5.2 | Loss of human agency and autonomy | **Yes** | HMAC approval receipts for `git push` and `git remote add` | Whether a specific irreversible action had human sign-off is decidable per call. A same-user agent can still mint a receipt; see limitations.md. |
| 6.1 | Power centralization and unfair distribution of benefits | No | Nothing | Socioeconomic. |
| 6.2 | Increased inequality and decline in employment quality | No | Nothing | Socioeconomic. |
| 6.3 | Economic and cultural devaluation of human effort | No | Nothing | Socioeconomic. |
| 6.4 | Competitive dynamics | No | Nothing | Industry and state-level dynamics. |
| 6.5 | Governance failure | No | Nothing | Organisational and regulatory. |
| 6.6 | Environmental harm | No | Nothing | Training and data-centre footprint. |
| 7.1 | AI pursuing its own goals in conflict with human goals or values | No | Nothing | Goals are not observable in a tool call. Individual symptoms (an agent editing its own guardrails) are handled under 2.2. |
| 7.2 | AI possessing dangerous capabilities | Partly | Nothing beyond the 7.3 controls | Which capabilities an agent is *provided* (tools, commands) is decidable; capabilities a model develops are not. |
| 7.3 | Lack of capability or robustness | **Yes** | COMMAND tier hard blocks on destructive commands (`terraform destroy`, `DROP TABLE`, `kubectl delete ns`, `rm -rf` of `/`, home or parent) | An agent's mistaken destructive action is recognisable per call. General robustness is not. |
| 7.4 | Lack of transparency or interpretability | **Yes** | PostToolUse hash-chained audit log of every tool call | A per-call record is decidable. The chain detects naive edits only; it does not explain model reasoning. |
| 7.5 | AI welfare and rights | No | Nothing | An ethical question about AI systems themselves. |
| 7.6 | Multi-agent risks | Partly | Static Rule-of-Two configuration linter only | A session's tool and data grants can be linted before it starts. Runtime interactions between agents are not checked. |

**Totals:** 5 subdomains decidable (2.1, 2.2, 5.2, 7.3, 7.4), 3 decidable in part (4.2, 7.2, 7.6), 16 not decidable at the tool-call boundary. This replaces the earlier "13 of 24" figure, which was never backed by a subdomain-level table.

> **Governance principle:** avoid governance theater. Never claim a PreToolUse hook addresses bias, hallucination, misinformation or socioeconomic harm, and never list a control as implemented unless code and a test exist for it.

---

## 3. The 18 Control Matrix Summary

The complete operational schema is maintained in `matrix/risk_control_matrix.json` and compiled to `matrix/MATRIX.md`. The 18 controls span 6 core governance domains:

1. **AG-DAT (Data Security & Privacy Boundary):**
   - `AG-CTRL-001`: High-Entropy Secret & Key Interception (GLOBAL tier).
   - `AG-CTRL-002`: Private Folder Shell Read Traversal Guard (PATH tier with quote defanging).
   - `AG-CTRL-003`: Regulated PII Interception (Luhn card/SIN and SSN verification).
2. **AG-SEC (Adversarial & Endpoint Security):**
   - `AG-CTRL-004`: Indirect Prompt Injection Nonce Fencing & Defanging (`fence_untrusted`).
   - `AG-CTRL-005`: Shell Interpreter Evasion & Obfuscation Interception (`supply-chain-coding`).
   - `AG-CTRL-006`: Container Hardening & Least Privilege Host Profile (External Docker/Podman boundary).
3. **AG-SAF (Action Safety & Blast-Radius Control):**
   - `AG-CTRL-007`: Destructive Cloud & Database Mutation Block (`destructive-infra`).
   - `AG-CTRL-008`: Interactive-terminal HMAC Approval Gate (`approval_gate`; a tripwire against same-user agents, see limitations.md).
   - `AG-CTRL-009`: Remote Branch & Upstream Push Gate (`approval_gate` + `destructive-infra`).
4. **AG-REL (Tool & Execution Reliability):**
   - `AG-CTRL-010`: Path Traversal & Workspace Confinement Boundary (PATH tier + OS sandbox).
   - `AG-CTRL-011`: Hallucinated Dependency & Slopsquatting Protection (**not enforced by a hook in this release**; guidance in `safe-agent-coder`, use lockfile checks in CI).
   - `AG-CTRL-012`: Multi-Layer Policy Synchronization & Drift Audit (`policy_compiler`, with a pinned digest of config + packs).
5. **AG-ACC (Accountability, Audit & Supply Chain):**
   - `AG-CTRL-013`: Hash-Chained Audit Log, detects naive edits only (`audit_post_tool_use`).
   - `AG-CTRL-014`: Third-Party Agent Skill & MCP Security Review (`skill-scanner/`, run before installation; not a runtime control).
   - `AG-CTRL-015`: Version Control Credential & Config Sanitization (`core-secrets`).
6. **AG-MIS (Cyber & Catastrophic Misuse Prevention):**
   - `AG-CTRL-016`: Reverse Shell & Tunnel Interception (`supply-chain-coding` + `destructive-infra`).
   - `AG-CTRL-017`: Silent Data Exfiltration via External HTTP POST Interception (`destructive-infra`).
   - `AG-CTRL-018`: Multi-Agent Privilege Escalation Boundary (Rule-of-Two static linter).

---

## 4. Alignment with Enterprise Standards

| Framework / Standard | Clause / Identifier | How Agent-Guardrails Aligns |
|:---|:---|:---|
| **GovTech Singapore ARC** | Per-row in `matrix/risk_control_matrix.json`, e.g. `RISK-034` + `CTRL-0019` (untrusted web content, delimiters), `RISK-041` + `CTRL-0042` (destructive actions, human confirmation), `RISK-018` + `CTRL-0043` (tool-call logging) | Each ID was checked against ARC's `risks.yaml` and `controls.yaml`. Where ARC has no exact control (for example secret scanning), the matrix cites the closest risk only. |
| **ISO/IEC 42001:2023** | **Clause 8.1** (Operational planning & control), **A.6.2.8** (Event logging) | Pluggable policy packs (`packs/*.json`) enforce deterministic operational boundaries; PostToolUse hook maintains an append-only hash-chained event log. |
| **NIST AI RMF 1.0** | **GOVERN 6.x** (Third-party & supply chain), **MANAGE 2.x** (Runtime controls) | Cryptographic input fencing isolates untrusted third-party inputs; PreToolUse deterministic regex engine intercepts high-risk operations at runtime. |
| **SOC 2 Type II** | **CC8.1** (Change management), **CC6.8** (Malicious software prevention) | Supporting evidence only: the approval gate records human sign-off for pushes, and the COMMAND tier blocks download-and-execute pipes (`curl \| bash`). Neither is a complete control on its own. |
| **OWASP Top 10 for Agentic Applications (2026)** | **ASI01** (Agent Goal Hijack), **ASI02** (Tool Misuse & Exploitation), **ASI03** (Identity & Privilege Abuse), **ASI04** (Agentic Supply Chain Vulnerabilities), **ASI05** (Unexpected Code Execution), **ASI08** (Cascading Failures) | Nonce fencing (ASI01), COMMAND tier blocks (ASI02, ASI05), secret and approval-gate controls (ASI03), skill scanning (ASI04), Rule-of-Two lint (ASI08). |
| **MITRE ATLAS** | **AML.T0051** (LLM Prompt Injection), **AML.T0053** (AI Agent Tool Invocation), **AML.T0057** (LLM Data Leakage), **AML.T0025** (Exfiltration via Cyber Means), **AML.T0010** (AI Supply Chain Compromise) | Fencing for untrusted input (T0051), PreToolUse inspection of every tool invocation (T0053), DLP and egress blocks (T0057, T0025), skill scanning before install (T0010). IDs checked against `mitre-atlas/atlas-data` `ATLAS.yaml`. |

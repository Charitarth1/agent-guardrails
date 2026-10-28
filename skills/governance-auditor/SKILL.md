---
name: governance-auditor
description: Automated AI governance, runtime security auditing, and compliance verification for agentic systems. Use when conducting repository security audits, validating PreToolUse hook configurations, assessing agent permissions against the Risk & Control Matrix, or compiling compliance evidence.
version: 1.1.0
author: Charitarth Bharti / SafeAIGuy
license: Apache-2.0
---

# Governance Auditor (`governance-auditor`)

> Enterprise compliance screening, runtime hook validation, and risk-matrix auditing for autonomous agent harnesses.

## Purpose & Overview

The **Governance Auditor** provides automated auditing workflows to verify whether an AI agent harness (Claude Code, Cursor, Antigravity, OpenHands, etc.) adheres to deterministic safety controls, avoids common configuration vulnerabilities, and meets the 18 runtime controls defined in the `matrix/risk_control_matrix.json`.

---

## 1. The Audit Scope: What a Tool-Call Hook Can Decide (Our Classification)

When auditing an AI agent implementation, avoid "governance theater." The MIT AI Risk Repository defines 24 risk subdomains and does not classify them by runtime decidability. Our classification (`docs/agentic_risk_screener.md`, section 2) is:

- **Decidable at the tool-call boundary (5):** 2.1 privacy and sensitive-data leakage, 2.2 AI system security attacks, 5.2 loss of human agency, 7.3 lack of robustness, 7.4 lack of transparency.
- **Decidable in part (3):** 4.2 cyberattacks (shell and tunnel commands only), 7.2 dangerous capabilities (tools granted), 7.6 multi-agent risks (static lint only).
- **Not decidable here (16):** for example bias, toxicity, misinformation, fraud, overreliance, socioeconomic and environmental harms. Never report a hook as a control for these.

Report a control as PASS only if code and a passing test exist for it. Matrix rows marked "Not enforced" (for example AG-RISK-011) are guidance, not controls.

---

## 2. The 5-Point Self-Audit Checklist (Audit Finding Regression Guards)

Verify the agent configuration against the lessons learned from real-world self-audits:

### Checklist Item 1: Hook Schema Nesting (F-1)
- In Claude Code and similar harnesses, hook configurations formatted as a flat `{matcher, command}` object are **silently ignored**!
- **Requirement:** Ensure configuration uses nested arrays with universal `.*` matcher:
  ```json
  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": ".*",
          "hooks": [
            { "type": "command", "command": "sh -c 'python3 \"$0\" \"$@\"; rc=$?; [ $rc -eq 0 ] || exit 2' '/path/to/src/dlp_pre_tool_use.py'" }
          ]
        }
      ]
    }
  }
  ```

### Checklist Item 2: Approval Gate Tamper-Resistance (F-0, F-3)
- Ensure approval receipts cannot be forged by model chat outputs, and record that a same-user agent can still mint one (see `docs/limitations.md`).
- **Requirement:** Minting must require an interactive terminal with no bypass flag or environment variable, receipts must be HMAC-SHA256 signed and single-use, and malformed or `NaN` timestamps must fail closed with exit code 2. For a real boundary, the signing secret must be unreadable by the agent's OS user.

### Checklist Item 3: Denylist Floor Union (F-5)
- If an agent project links an external registry file (e.g. `projects.json`), reading failures or local edits must NEVER shrink the denylist.
- **Requirement:** The active denylist must always be the union `DENYLIST_FLOOR ∪ REGISTRY`.

### Checklist Item 4: Quote Defanging for Path and Command Traversal (F-16)
- Agents can attempt to evade path and command filters using shell quoting: `cat ~/Projects/'private-vault'/keys` or `g'i't pu''sh`.
- **Requirement:** The hook must evaluate both raw strings and defanged strings (`' " \ \ ` removed, whitespace collapsed, SQL comments stripped).

### Checklist Item 5: Hash-Chained Audit Log (F-4)
- The chain detects naive edits only. Anyone with write access can truncate or rewrite it; ship records to a collector the agent cannot write to if you need integrity.
- **Requirement:** Each record must contain a sequential number (`seq`) and a SHA-256 hash chaining to the previous record (`prev_hash`). Never log raw credential payloads or database passwords into the audit log.

---

## 3. Auditing Workflows

### Command 1: Validate Harness Configuration
Run the automated configuration auditor:
```bash
guardrails audit-config --settings-file .claude/settings.json
```

### Command 2: Verify Audit Log Integrity
Check whether any audit records have been tampered with or deleted:
```bash
guardrails verify-log --log tool_audit.jsonl
```

### Command 3: Export Risk & Control Matrix Report
Generate a compliance evidence document mapping all 18 risks to active controls:
```bash
guardrails compliance-export --format markdown --out AUDIT_REPORT.md
```

---

## 4. Governance Audit Report Template

When delivering a repository or pipeline audit to stakeholders, format findings as follows:

```markdown
# Agent Governance & Security Audit Report

## 1. Executive Summary
- **Target Repository / Harness:** [Name/Path]
- **Audit Date:** [ISO Date]
- **Audit Verdict:** [PASSED | REMEDIATION REQUIRED]

## 2. Control Matrix Compliance (18 Controls)
| ID | Domain | Control ID | Control Name | Status | Enforcement Mechanism |
|:---|:---|:---|:---|:---|:---|
| AG-RISK-001 | Security | AG-CTRL-001 | Core Credentials Firewall | PASS | PreToolUse GLOBAL Regex |
| AG-RISK-002 | Security | AG-CTRL-002 | Denylisted Directory Containment | PASS | PreToolUse PATH Regex |
| AG-RISK-007 | Security | AG-CTRL-007 | Terminal Human Approval Gate | PASS | Out-of-band HMAC Gate |
| AG-RISK-004 | Safety | AG-CTRL-004 | Cryptographic Nonce Fencing | PASS | Nonce Fencing Utility |
| AG-RISK-013 | Accountability | AG-CTRL-013 | Hash-Chained Audit Log | PASS | SHA-256 chain (detects naive edits) |
```

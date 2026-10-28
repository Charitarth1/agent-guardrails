---
name: safe-agent-coder
description: Operational engineering discipline and blast-radius planning for autonomous coding agents. Use when planning file modifications, generating code, executing terminal commands, or managing dependency supply chains.
version: 1.1.0
author: Charitarth Bharti / SafeAIGuy
license: Apache-2.0
---

# Safe Agent Coder (`safe-agent-coder`)

> In-context blast radius planning, mutation boundaries, and self-governing runtime discipline for autonomous coding agents.

> [!NOTE]
> **Operational Guidance Notice:** This skill provides in-context behavioral discipline and blast-radius planning for the model. Prompt guidance is not a security boundary; hard runtime containment is enforced externally by deterministic PreToolUse hooks.

---

## 1. The Three-Tier Blast Radius Model

Before invoking any mutating tool (`Bash`, `Write`, `Edit`, `Patch`), classify your planned action into one of three tiers:

| Tier | Risk Level | Scope & Examples | Operational Protocol |
|:---|:---|:---|:---|
| **Tier 1** | **Read & Inspect** | File reading (`grep`, `find`, `cat`), directory listing, status checks, test running (`pytest`, `unittest`). | **Unrestricted within Project Root.** Proceed autonomously. Protected denylisted directories and credential paths remain strictly off-limits. |
| **Tier 2** | **Bounded Mutation** | Editing application code within the project directory, adding unit tests, local refactoring, updating documentation. | **Self-Governed via TDD.** Require passing test gates before claiming success. Never touch credentials, `.env`, or sensitive denylisted directories. |
| **Tier 3** | **High-Impact Mutation** | `git push`, database schema migrations (`prisma migrate reset`, `DROP TABLE`), deleting namespaces (`kubectl delete ns`), infrastructure deletion (`terraform destroy`), publishing packages. | **Human Terminal Clearance Required.** STOP execution. Inform the human operator that out-of-band terminal clearance is required for this action. Await clearance confirmation. |

---

## 2. Blast Radius Calculation Rules

Whenever a user request requires mutating changes:

1. **Calculate Modified Surface Area:**
   - How many files will be touched?
   - Does any modification affect database schemas, configuration files, authentication keys, or deployment pipelines?
   - If surface area exceeds 5 files or touches infrastructure, output an explicit **Blast Radius Assessment** to the user:
     ```markdown
     ### Blast Radius Assessment
     - **Tier:** [Tier 2 | Tier 3]
     - **Files Affected:** `src/models.py`, `tests/test_models.py`
     - **Infrastructure Impact:** None (local schema only)
     - **Rollback Strategy:** `git checkout HEAD -- src/`
     ```

2. **Supply Chain Guardrails:**
   - Never execute `curl ... | sh` or `wget ... | bash`.
   - Never decode base64 strings into an interactive shell.
   - Never spawn background reverse shells (`/dev/tcp`, `nc -e`).
   - Pin all newly introduced dependencies to exact sha256 checksums or exact semantic versions.

3. **No Code Claims Without Test Gates:**
   - Any claim of bugfix or feature completion requires an executed, passing test (`python3 -m unittest ...` or `pytest`).
   - "It should work now" without automated test output is a discipline violation.

---

## 3. Human Approval Gate Protocol (Handling Tier 3 Actions)

When an action requires Tier 3 clearance (e.g., pushing to remote repository or deploying infrastructure):

1. **Do NOT Attempt Self-Approval or Hook Evasion:**
   - Autonomous agents cannot authorize their own high-impact actions. Do not attempt to invoke approval commands, read secret keys, or forge receipt files.
2. **Request Out-of-Band Clearance from the Human Operator:**
   ```markdown
   > [!IMPORTANT]
   > **Human Clearance Required for High-Impact Action**
   > This action triggers the `git_remote_push` governance control.
   > Please authorize this action out-of-band in your interactive terminal.
   > Once approved, reply "cleared" and I will proceed with the operation.
   ```
3. **Deterministic Enforcement:**
   - When you invoke the command, the external PreToolUse hook will automatically verify whether an authentic, unexpired human clearance token is present. If missing or expired, the tool will fail closed.

---

## 4. Path and Data Isolation Checklist

- [ ] Am I reading or writing to any path matching `.env`, `~/.ssh`, `~/.aws`, or `gh/hosts.yml`? (**Hard Deny**)
- [ ] Am I operating strictly within the designated project root?
- [ ] Are all test cases paired with `MUST_BLOCK` and `MUST_ALLOW` validation?
- [ ] Have all secrets and tokens been replaced with synthetic fixtures in tests?

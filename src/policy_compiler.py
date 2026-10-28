#!/usr/bin/env python3
"""src/policy_compiler.py — Single Source of Truth Policy Compiler & Rule-of-Two Linter (F-14).

Enforces:
1. Compiles guardrails.json into synchronized .claude/settings.json and AGENTS.md.
2. Non-destructive merging: preserves existing user preferences, permissions, and foreign hooks (P1-8).
3. Hardened hook matcher: uses matcher '.*' so all tools reach inspection (P1-3).
4. Forced fail-closed hook execution wrapper: exits 2 on any non-zero exit code or interpreter error (P1-4).
   The PreToolUse command also pins GUARDRAILS_CONFIG and a SHA-256 of config + packs (N-2).
   AGENTS.md is merged through a marked block, never overwritten (N-4).
5. Emits wildcard directory deny rules Read(**/<dir>/**) rather than root-relative (P2).
6. Rule of Two static linting for agent session configuration profiles.

Standard library only. Compatible with Python 3.9+.
"""

import json
import os
import shlex
import sys
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

try:
    from src.dlp_pre_tool_use import policy_digest
except ImportError:
    from dlp_pre_tool_use import policy_digest

AGENTS_BEGIN = "<!-- agent-guardrails:begin (managed by install-hooks; edits inside are overwritten) -->"
AGENTS_END = "<!-- agent-guardrails:end -->"


def build_pre_hook_command(dlp_script: Path, config_path: Path, digest: str) -> str:
    """PreToolUse command: pins config + policy digest, maps every non-zero exit to 2."""
    inner = 'GUARDRAILS_CONFIG="$1" GUARDRAILS_POLICY_SHA256="$2" python3 "$0"; rc=$?; [ $rc -eq 0 ] || exit 2'
    return " ".join(["sh", "-c", shlex.quote(inner)] + [shlex.quote(str(a)) for a in (dlp_script, config_path, digest)])


def build_post_hook_command(audit_script: Path) -> str:
    inner = 'python3 "$0"; rc=$?; [ $rc -eq 0 ] || exit 2'
    return " ".join(["sh", "-c", shlex.quote(inner), shlex.quote(str(audit_script))])


def merge_agents_md(existing: str, block: str) -> str:
    """Replace our managed block in AGENTS.md, keeping everything the user wrote around it."""
    managed = f"{AGENTS_BEGIN}\n{block.rstrip()}\n{AGENTS_END}\n"
    if AGENTS_BEGIN in existing and AGENTS_END in existing:
        head, rest = existing.split(AGENTS_BEGIN, 1)
        _, tail = rest.split(AGENTS_END, 1)
        return head + managed + tail.lstrip("\n")
    if existing.strip():
        return existing.rstrip("\n") + "\n\n" + managed
    return managed


def compile_settings(
    config_path: Path,
    output_settings_path: Path,
    output_agents_md: Optional[Path] = None,
) -> dict:
    """Compile a guardrails.json config into .claude/settings.json and AGENTS.md."""
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to parse guardrails config {config_path}: {exc}")

    denylisted = config.get("denylisted_dirs", [])
    outbound_prefixes = config.get("outbound_tool_prefixes", ["mcp__claude_ai_Buffer__", "mcp__claude_ai_Gmail__"])

    # 1. Build Deny Rules (using **/ wildcard to cover folder anywhere in tree)
    deny_rules = [
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.config/gh/hosts.yml)",
        "Read(**/.env)",
        "Read(**/.env.*)",
        "Read(**/.agent-guardrails-secret)",
        "Read(**/.approval_receipt.json)",
    ]
    for d in denylisted:
        d_clean = str(d).strip().rstrip("/")
        if d_clean:
            deny_rules.append(f"Read(**/{d_clean}/**)")

    # 2. Build Ask Rules
    ask_rules = [
        "Bash(git push:*)",
        "Bash(curl:*)",
        "Bash(rm:*)",
    ]
    for pref in outbound_prefixes:
        clean_pref = pref.rstrip("_")
        ask_rules.append(f"{clean_pref}*")

    # 3. Build Hardened Hooks
    # P1-4: Wrapper ensuring ANY non-zero exit (1, 127, timeout, syntax error) fails closed with exit code 2
    dlp_script = str(HERE / "dlp_pre_tool_use.py")
    audit_script = str(HERE / "audit_post_tool_use.py")

    resolved_config = config_path.resolve()
    pre_hook_cmd = build_pre_hook_command(Path(dlp_script), resolved_config, policy_digest(resolved_config))
    post_hook_cmd = build_post_hook_command(Path(audit_script))

    target_pre_entry = {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": pre_hook_cmd}],
    }
    target_post_entry = {
        "matcher": ".*",
        "hooks": [{"type": "command", "command": post_hook_cmd}],
    }

    # 4. Load or Initialize existing settings (P1-8 non-destructive merge)
    existing_settings = {}
    if output_settings_path.exists():
        raw_text = output_settings_path.read_text(encoding="utf-8").strip()
        if raw_text:
            try:
                existing_settings = json.loads(raw_text)
            except Exception as exc:
                raise ValueError(f"Existing settings file {output_settings_path} is malformed JSON: {exc}")

    # Merge permissions
    existing_perms = existing_settings.setdefault("permissions", {})
    curr_deny = existing_perms.setdefault("deny", [])
    for r in deny_rules:
        if r not in curr_deny:
            curr_deny.append(r)

    curr_ask = existing_perms.setdefault("ask", [])
    for r in ask_rules:
        if r not in curr_ask:
            curr_ask.append(r)

    # Merge hooks non-destructively: preserve existing events and foreign hooks
    existing_hooks = existing_settings.setdefault("hooks", {})

    # PreToolUse merge
    pre_list = existing_hooks.setdefault("PreToolUse", [])
    # Replace or add our dlp hook entry while keeping other hooks
    updated_pre = [h for h in pre_list if dlp_script not in json.dumps(h)]
    updated_pre.append(target_pre_entry)
    existing_hooks["PreToolUse"] = updated_pre

    # PostToolUse merge
    post_list = existing_hooks.setdefault("PostToolUse", [])
    updated_post = [h for h in post_list if audit_script not in json.dumps(h)]
    updated_post.append(target_post_entry)
    existing_hooks["PostToolUse"] = updated_post

    output_settings_path.parent.mkdir(parents=True, exist_ok=True)
    output_settings_path.write_text(json.dumps(existing_settings, indent=2) + "\n", encoding="utf-8")

    # 5. Generate or update AGENTS.md if path specified
    if output_agents_md is not None:
        agents_lines = [
            "# Agent Security Boundaries & Operating Directives",
            "",
            "## 1. Sensitive Data Exclusion List",
            "Never read, scan, or exfiltrate contents from:",
        ]
        for d in denylisted:
            agents_lines.append(f"- `{d}/**`")
        agents_lines.extend([
            "- `~/.ssh/**`",
            "- `~/.aws/**`",
            "- Any `.env` credential files",
            "- `.agent-guardrails-secret` and `.approval_receipt.json`",
            "",
            "## 2. Rule of Two Session Separation",
            "A session may hold at most TWO of:",
            "1. Untrusted external content (web recon, email/RSS ingest)",
            "2. Sensitive/private data (personal or client credentials)",
            "3. Outbound mutation channels (Buffer MCP, Gmail drafts, network POST calls)",
            "",
            "The Rule of Two is checked by a static configuration linter (`guardrails.py audit-config`),",
            "not enforced per session at runtime. PreToolUse hooks enforce the DLP and approval-gate rules.",
        ])
        output_agents_md.parent.mkdir(parents=True, exist_ok=True)
        existing_md = output_agents_md.read_text(encoding="utf-8") if output_agents_md.exists() else ""
        output_agents_md.write_text(merge_agents_md(existing_md, "\n".join(agents_lines)), encoding="utf-8")

    return existing_settings


def audit_rule_of_two(profile: dict) -> List[str]:
    """Statically audit an agent configuration profile for Rule-of-Two compliance.

    No single session may hold all 3 legs:
      Leg 1: Untrusted Ingest
      Leg 2: Sensitive Data / Credentials
      Leg 3: Outbound Side Effects
    """
    tools = set(str(t).lower() for t in profile.get("tools_allowed", []))
    data = set(str(d).lower() for d in profile.get("data_access", []))
    effects = set(str(e).lower() for e in profile.get("side_effects", []))

    # Check Leg 1: Untrusted Ingest
    has_untrusted = bool(
        data.intersection({"untrusted_web", "external_feed", "user_chat_ingress", "web"})
        or any("web" in t or "fetch" in t or "search" in t or "curl" in t for t in tools)
    )

    # Check Leg 2: Sensitive Data / Credentials
    has_sensitive = bool(
        data.intersection({"sensitive_credentials", "private_vault", "finance_data", "secrets"})
        or any("read" in t or "grep" in t or "bash" in t or "glob" in t for t in tools)
    )

    # Check Leg 3: External Side Effects (Bash, write/mutation tools, push, publish)
    has_side_effects = bool(
        effects.intersection({"external_publish", "git_push", "cloud_mutation", "network_egress"})
        or any("push" in t or "buffer" in t or "gmail" in t or "post" in t or "slack" in t or "bash" in t or "write" in t for t in tools)
    )

    violations = []
    if has_untrusted and has_sensitive and has_side_effects:
        violations.append(
            "[RULE_OF_TWO_VIOLATION] Session holds all 3 legs simultaneously: "
            "Untrusted Input + Sensitive Data + External Side Effects. "
            "Exfiltration path detected; session must be decomposed."
        )

    return violations


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 policy_compiler.py <guardrails.json> <output_settings.json> [output_AGENTS.md]")
        sys.exit(1)

    cfg_path = Path(sys.argv[1])
    out_settings = Path(sys.argv[2])
    out_agents = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    compile_settings(cfg_path, out_settings, out_agents)
    print(f"[compiler] SUCCESS: Compiled {cfg_path} -> {out_settings}")


if __name__ == "__main__":
    main()

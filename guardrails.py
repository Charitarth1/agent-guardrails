#!/usr/bin/env python3
"""guardrails.py — Enterprise AI Agent Guardrails Root CLI & Orchestrator.

Zero-dependency CLI for agent safety, deterministic runtime firewalls,
cryptographic input fencing, out-of-band approval gates, and governance auditing.

Subcommands:
  init               Initialize guardrails configuration, audit log, and secrets
  install-hooks      Compile and wire runtime PreToolUse/PostToolUse hooks into harness settings
  check              Inspect tool call payloads against active DLP tiers
  fence              Wrap untrusted external text in cryptographic nonce fencing
  approve            Mint an HMAC-signed terminal approval token (interactive terminal only)
  verify-log         Validate SHA-256 hash-chaining in the audit log
  audit-config       Audit harness configuration schemas and Rule-of-Two separation
  vendor-skills      Install downloadable agent skills to target harnesses (.claude, .cursor, .gemini)
  compliance-export  Export the 18-risk control matrix in Markdown or JSON
  test               Execute the internal test suite

Standard library only. Compatible with Python 3.9+.
"""

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from src.approval_gate import mint_receipt, verify_receipt, MAX_TTL_MINUTES
from src.audit_post_tool_use import verify_audit_log
from src.dlp_pre_tool_use import DLPEngine, evaluate_tool_call
from src.fence_untrusted import fence_text
from src.policy_compiler import audit_rule_of_two, compile_settings


def cmd_init(args) -> int:
    """Initialize local guardrails configuration and environment."""
    target_dir = Path(args.dir).resolve() if args.dir else Path.cwd()
    config_file = target_dir / "guardrails.json"
    audit_log = target_dir / "tool_audit.jsonl"
    secret_file = Path.home() / ".agent-guardrails-secret"

    # 1. Create guardrails.json if missing (using clean synthetic examples)
    if not config_file.exists():
        default_config = {
            "active_packs": [
                "core-secrets",
                "destructive-infra",
                "supply-chain-coding",
                "pii-regulated",
                "personal-privacy",
            ],
            "denylisted_dirs": [
                "private-vault",
                "finance-records",
                "sensitive-notes",
            ],
            "term_denylist_files": ["dlp_denylist.local.txt"],
            "audit_log": "tool_audit.jsonl",
            "exec_tool_names": ["bash", "exec", "process", "code_execution", "shell"],
            "outbound_tool_prefixes": [
                "mcp__claude_ai_buffer__",
                "mcp__claude_ai_gmail__",
                "publish",
                "send_email",
            ],
        }
        config_file.write_text(json.dumps(default_config, indent=2) + "\n", encoding="utf-8")
        print(f"Created config: {config_file}")
    else:
        print(f"Existing config found: {config_file}")

    # 2. Seed audit log if missing
    if not audit_log.exists():
        audit_log.touch()
        print(f"Initialized audit ledger: {audit_log}")

    # 3. Create HMAC secret if missing (atomic 0600)
    if not secret_file.exists():
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret = secrets.token_bytes(32)
        fd = os.open(str(secret_file), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        print(f"Generated HMAC secret (0600): {secret_file}")

    print("\nInitialization complete. Guardrails active.")
    return 0


def cmd_install_hooks(args) -> int:
    """Compile and wire PreToolUse and PostToolUse hooks into agent harness settings."""
    cfg_path = Path(args.config) if args.config else Path.cwd() / "guardrails.json"
    if not cfg_path.exists():
        if (REPO_ROOT / "guardrails.json").exists():
            cfg_path = REPO_ROOT / "guardrails.json"
        elif (REPO_ROOT / "claude-code" / "hooks" / "guardrails.example.json").exists():
            cfg_path = REPO_ROOT / "claude-code" / "hooks" / "guardrails.example.json"
        else:
            # Seed default config if none found
            cmd_init(argparse.Namespace(dir=str(Path.cwd())))
            cfg_path = Path.cwd() / "guardrails.json"

    settings_path = Path(args.settings or Path.cwd() / ".claude" / "settings.json")
    agents_path = Path(args.agents_md or Path.cwd() / "AGENTS.md")

    try:
        compile_settings(cfg_path, settings_path, agents_path)
        print(f"[install-hooks] SUCCESS: Compiled runtime hooks into {settings_path}")
        print(f"[install-hooks] SUCCESS: Synchronized security directives in {agents_path}")
        return 0
    except Exception as exc:
        print(f"[install-hooks] FAILED: {exc}", file=sys.stderr)
        return 2


def cmd_check(args) -> int:
    """Inspect a payload against active DLP policies."""
    payload = args.payload
    if payload is None and args.file:
        p = Path(args.file)
        if p.exists():
            payload = p.read_text(encoding="utf-8")
        else:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            return 2

    if payload is None:
        if not sys.stdin.isatty():
            payload = sys.stdin.read()
        else:
            print("Error: No payload provided via --payload, --file, or stdin.", file=sys.stderr)
            return 2

    try:
        # A human-run check may use the project's guardrails.json; only the hook
        # must never trust the working directory (it gets GUARDRAILS_CONFIG pinned).
        cfg = Path(args.config) if args.config else (Path.cwd() / "guardrails.json")
        engine = DLPEngine(config_path=cfg if cfg.exists() else None)
        # --no-approval-check disables checking receipts (treats all approval-required actions as blocked)
        allow_receipt_bypass = not args.no_approval_check
        block = engine.check(payload, tool_name=args.tool, check_approval=allow_receipt_bypass)
        if block:
            msg = (
                f"BLOCKED: rule='{block['rule_id']}', tier='{block['tier']}'. {block['description']}"
            )
            print(msg, file=sys.stderr)
            return 2

        if args.verbose:
            print(f"ALLOWED: tool={args.tool}")
        return 0
    except Exception as exc:
        # P1-4: Always fail closed with exit code 2
        print(f"BLOCKED: Check failed with error ({type(exc).__name__}: {exc}); failing closed.", file=sys.stderr)
        return 2


def cmd_fence(args) -> int:
    """Wrap untrusted input in cryptographic nonce fencing."""
    content = args.text
    if content is None and args.file:
        p = Path(args.file)
        if p.exists():
            content = p.read_text(encoding="utf-8")
        else:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            return 2

    if content is None:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            print("Error: No content provided via --text, --file, or stdin.", file=sys.stderr)
            return 2

    fenced, is_quarantined, category = fence_text(content, source=args.source or "unknown")
    print(fenced)

    # P1-9: Return exit code 2 on quarantine trigger
    if is_quarantined:
        print(f"[fence] ALERT: Quarantined adversarial pattern '{category}'.", file=sys.stderr)
        return 2

    return 0


def cmd_approve(args) -> int:
    """Mint an out-of-band HMAC approval token on the local interactive terminal."""
    receipt_file = Path(args.receipt_file) if args.receipt_file else None
    secret_file = Path(args.secret_file) if args.secret_file else None

    scope = args.scope.strip().lower()
    if scope == "all" or "*" in scope:
        print("Error: Wildcard scope 'all' is prohibited. Specify exact action scope (e.g. 'git_remote_push').", file=sys.stderr)
        return 2

    try:
        receipt = mint_receipt(
            scope=scope,
            ttl_minutes=args.ttl,
            reviewer=args.reviewer,
            receipt_path=receipt_file,
            secret_path=secret_file,
        )
        print(" Clearance Granted by Human Operator:")
        print(f"  - Scope:       {receipt['scope']}")
        print(f"  - Expires At:  {receipt['expires_at']} (UTC)")
        print(f"  - Reviewer:    {receipt['reviewer']}")
        print(f"  - Token:       {receipt['token']}")
        print(f"  - HMAC-SHA256: {receipt['hmac'][:16]}...")
        return 0
    except Exception as exc:
        print(f"Approval failed: {exc}", file=sys.stderr)
        return 2


def cmd_verify_log(args) -> int:
    """Verify unbroken SHA-256 hash chaining throughout the audit log."""
    log_path = Path(args.log) if args.log else None
    is_valid, reason, count = verify_audit_log(log_path)
    if is_valid:
        print(f"VALID: Audit log integrity verified across {count} record(s). Unbroken SHA-256 chain.")
        return 0
    else:
        print(f"TAMPER DETECTED: {reason}", file=sys.stderr)
        return 1


def cmd_audit_config(args) -> int:
    """Audit settings files or session profiles for schema bugs and Rule of Two."""
    failures = 0
    if args.settings_file:
        sf = Path(args.settings_file)
        if not sf.exists():
            print(f"Error: settings file {sf} not found", file=sys.stderr)
            return 1
        try:
            data = json.loads(sf.read_text(encoding="utf-8"))
            hooks = data.get("hooks", {})
            for hook_name, entries in hooks.items():
                if isinstance(entries, list):
                    for entry in entries:
                        if "command" in entry and "hooks" not in entry:
                            print(f"CRITICAL [F-1 Bug]: Hook '{hook_name}' contains flat 'command' field. Claude Code requires a nested 'hooks' array.", file=sys.stderr)
                            failures += 1
        except Exception as exc:
            print(f"Error parsing {sf}: {exc}", file=sys.stderr)
            failures += 1

    if args.profile_file:
        pf = Path(args.profile_file)
        if pf.exists():
            try:
                profile = json.loads(pf.read_text(encoding="utf-8"))
                violations = audit_rule_of_two(profile)
                if violations:
                    for v in violations:
                        print(f"Rule of Two Violation: {v}", file=sys.stderr)
                    failures += len(violations)
            except Exception as exc:
                print(f"Error parsing profile {pf}: {exc}", file=sys.stderr)
                failures += 1

    if failures == 0:
        print("PASS: Configuration audit completed with 0 violations.")
        return 0
    return 1


def cmd_vendor_skills(args) -> int:
    """Export downloadable agent skills to target harnesses."""
    src_skills = REPO_ROOT / "skills"
    if not src_skills.exists():
        print(f"Error: skills directory not found at {src_skills}", file=sys.stderr)
        return 1

    target = args.target
    if args.dest_dir:
        dest_dir = Path(args.dest_dir)
    elif target == "claude-code":
        dest_dir = Path.cwd() / ".claude" / "skills"
    elif target == "cursor":
        dest_dir = Path.cwd() / ".cursor" / "rules"
    elif target == "antigravity":
        dest_dir = Path.cwd() / ".gemini" / "antigravity" / "skills"
    else:
        dest_dir = Path.cwd() / "skills"

    dest_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for skill_path in src_skills.iterdir():
        if skill_path.is_dir() and (skill_path / "SKILL.md").exists():
            skill_name = skill_path.name
            skill_content = (skill_path / "SKILL.md").read_text(encoding="utf-8")

            if target == "cursor":
                # Cursor rules expect .mdc files with globs frontmatter
                cursor_file = dest_dir / f"{skill_name}.mdc"
                if not skill_content.startswith("---"):
                    cursor_content = f"---\ndescription: {skill_name}\nglobs: *\n---\n\n{skill_content}"
                else:
                    cursor_content = skill_content.replace("---\n", "---\nglobs: *\n", 1)
                cursor_file.write_text(cursor_content, encoding="utf-8")
                print(f"Vendored Cursor rule: {skill_name} -> {cursor_file}")
            else:
                target_skill_dir = dest_dir / skill_name
                target_skill_dir.mkdir(parents=True, exist_ok=True)
                (target_skill_dir / "SKILL.md").write_text(skill_content, encoding="utf-8")
                print(f"Vendored skill: {skill_name} -> {target_skill_dir / 'SKILL.md'}")
            count += 1

    print(f"\nSuccessfully vendored {count} skill(s) into {dest_dir}")
    return 0


def cmd_compliance_export(args) -> int:
    """Export the 18-risk control matrix in Markdown or JSON format."""
    matrix_json_path = REPO_ROOT / "matrix" / "risk_control_matrix.json"
    if not matrix_json_path.exists():
        print(f"Error: matrix file not found at {matrix_json_path}", file=sys.stderr)
        return 1

    data = json.loads(matrix_json_path.read_text(encoding="utf-8"))
    out_format = args.format.lower()
    output_str = ""

    if out_format == "json":
        output_str = json.dumps(data, indent=2) + "\n"
    else:
        lines = [
            f"# Agentic Risk & Control Matrix ({data.get('framework_name', 'ARC-Aligned')})",
            f"**Version:** {data.get('version', '2.0.0')} | **License:** {data.get('license', 'Apache-2.0')}\n",
            "| ID | Domain | Risk Description | Control ID | Control Name | Tier | Enforcement |",
            "|:---|:---|:---|:---|:---|:---|:---|",
        ]
        for risk in data.get("risks", []):
            rid = risk.get("id", "")
            domain = risk.get("domain", "")
            desc = risk.get("description", "").replace("|", "\\|")
            ctrl = risk.get("control", {})
            cid = ctrl.get("id", "")
            cname = ctrl.get("name", "").replace("|", "\\|")
            tier = ctrl.get("tier", "")
            enf = ctrl.get("enforcement", "")
            lines.append(f"| `{rid}` | {domain} | {desc} | `{cid}` | {cname} | {tier} | {enf} |")
        output_str = "\n".join(lines) + "\n"

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        print(f"Exported compliance matrix ({out_format}) to {out_path}")
    else:
        print(output_str)

    return 0


def cmd_test(args) -> int:
    """Run the internal test suite."""
    test_cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    print(f"Executing test runner: {' '.join(test_cmd)}")
    proc = subprocess.run(test_cmd, cwd=REPO_ROOT)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="guardrails",
        description="Enterprise AI Agent Guardrails Root CLI & Deterministic Engine",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize local guardrails configuration")
    p_init.add_argument("--dir", help="Target directory (default: current directory)")

    # install-hooks
    p_inst = subparsers.add_parser("install-hooks", help="Compile and wire runtime hooks into harness settings")
    p_inst.add_argument("--config", help="Path to guardrails.json")
    p_inst.add_argument("--settings", help="Path to .claude/settings.json")
    p_inst.add_argument("--agents-md", help="Path to AGENTS.md")

    # check
    p_check = subparsers.add_parser("check", help="Inspect a payload against active DLP policies")
    p_check.add_argument("--tool", default="Bash", help="Tool name being invoked (default: Bash)")
    p_check.add_argument("--payload", help="String payload to check")
    p_check.add_argument("--config", help="Path to guardrails.json (default: ./guardrails.json if present)")
    p_check.add_argument("--file", help="File containing payload to check")
    p_check.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_check.add_argument("--no-approval-check", action="store_true", help="Disable receipt checking (treats all approval-required actions as blocked)")

    # fence
    p_fence = subparsers.add_parser("fence", help="Wrap untrusted text in cryptographic nonce fencing")
    p_fence.add_argument("--text", help="Text to fence")
    p_fence.add_argument("--file", help="File to read and fence")
    p_fence.add_argument("--source", help="Source URL or origin identifier")

    # approve
    # --scope is required (no default) so the COMMAND tier can recognise every CLI
    # mint attempt by its `approve ... --scope` shape; allow_abbrev=False stops `--sc`.
    p_approve = subparsers.add_parser(
        "approve", help="Mint an out-of-band HMAC approval token on the local terminal", allow_abbrev=False
    )
    p_approve.add_argument("--scope", required=True, help="Action scope to clear (e.g. git_remote_push)")
    p_approve.add_argument("--ttl", type=int, default=15, help="Validity duration in minutes (max 60)")
    p_approve.add_argument("--reviewer", default="", help="Reviewer username or ID")
    p_approve.add_argument("--receipt-file", help="Custom receipt output path")
    p_approve.add_argument("--secret-file", help="Custom secret key path")

    # verify-log
    p_verify = subparsers.add_parser("verify-log", help="Verify SHA-256 hash chaining of audit log")
    p_verify.add_argument("--log", help="Audit log path (default: tool_audit.jsonl)")

    # audit-config
    p_audit_cfg = subparsers.add_parser("audit-config", help="Audit harness configuration for schema bugs")
    p_audit_cfg.add_argument("--settings-file", help="Path to settings.json (Claude Code / Cursor)")
    p_audit_cfg.add_argument("--profile-file", help="Path to session profile JSON")

    # vendor-skills
    p_vendor = subparsers.add_parser("vendor-skills", help="Install downloadable skills into target harness")
    p_vendor.add_argument("--target", choices=["claude-code", "cursor", "antigravity"], help="Target harness")
    p_vendor.add_argument("--dest-dir", help="Custom destination directory for vendored skills")

    # compliance-export
    p_export = subparsers.add_parser("compliance-export", help="Export the 18-risk control matrix")
    p_export.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Export format")
    p_export.add_argument("--out", help="Output file path (default: stdout)")

    # test
    subparsers.add_parser("test", help="Execute the internal test suite")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        return 0

    command_map = {
        "init": cmd_init,
        "install-hooks": cmd_install_hooks,
        "check": cmd_check,
        "fence": cmd_fence,
        "approve": cmd_approve,
        "verify-log": cmd_verify_log,
        "audit-config": cmd_audit_config,
        "vendor-skills": cmd_vendor_skills,
        "compliance-export": cmd_compliance_export,
        "test": cmd_test,
    }

    handler = command_map.get(args.subcommand)
    if handler:
        return handler(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

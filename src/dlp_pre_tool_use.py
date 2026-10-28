#!/usr/bin/env python3
"""src/dlp_pre_tool_use.py — Core PreToolUse DLP Engine & Deterministic Runtime Firewall.

Enforces:
1. Four deterministic tiers: GLOBAL, PATH, COMMAND, OUTBOUND.
2. Dynamic pack compilation from packs/*.json (core-secrets, destructive-infra, supply-chain, etc.).
3. Recursive input extraction and command normalization (defang shell quotes, collapse whitespace, strip SQL comments).
4. Terminal HMAC approval gate integration (F-0, F-3: allows push/high-impact mutation only with valid receipt).
5. Post-approval continuation (P0-2: approval of one rule NEVER skips checking subsequent commands/rules).
6. Comprehensive Luhn validation across all matches via finditer (P1-7).
7. Self-protection: blocks any tool touching the gate secret/receipt, and file tools mutating
   guardrails.json, packs/, src/ or .claude/settings*.json. install-hooks also pins a digest of
   config + packs; any change after that fails closed (P0-1, N-2).
8. SHA-256 hash-chained audit logging (detects naive edits only) without leaking payloads.
9. Fail-closed contract for Claude Code and agent runtimes (Exit code 2 = BLOCK, 0 = ALLOW).

Standard library only. Compatible with Python 3.9+.
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
PACKS_DIR = REPO_ROOT / "packs"

try:
    from src.approval_gate import verify_receipt
except ImportError:
    try:
        from approval_gate import verify_receipt
    except ImportError:
        def verify_receipt(*args, **kwargs):
            return False, "approval_gate_module_missing"

try:
    from src.audit_post_tool_use import log_tool_action
except ImportError:
    try:
        from audit_post_tool_use import log_tool_action
    except ImportError:
        def log_tool_action(tool_name, status, details, log_path=None, cwd=None):
            return {"status": status}


def luhn_valid(digits: str) -> bool:
    """Validate numeric strings using the Luhn checksum formula."""
    if not digits.isdigit() or len(digits) < 2:
        return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def defang_shell_quoting(text: str) -> str:
    """Strip shell quotes and escape characters to counter path/command obfuscation (F-16, P1-1)."""
    return text.replace("'", "").replace('"', "").replace("\\ ", " ").replace("\\", "")


def normalize_command_text(text: str) -> str:
    """Normalize command text: defang quotes, strip SQL comments, strip zero-width chars, collapse whitespace."""
    # 1. Strip zero-width and invisible unicode characters
    t = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    # 2. Defang shell quotes
    t = defang_shell_quoting(t)
    # 3. Strip SQL multi-line comments (/* ... */)
    t = re.sub(r"/\*.*?\*/", " ", t, flags=re.DOTALL)
    # 4. Collapse all whitespace (including newlines) into single spaces
    t = re.sub(r"\s+", " ", t).strip()
    return t


DEFAULT_ACTIVE_PACKS = [
    "core-secrets",
    "destructive-infra",
    "supply-chain-coding",
    "pii-regulated",
    "personal-privacy",
]


def resolve_pack_file(name: str, packs_dir: Optional[Path] = None) -> Path:
    """Resolve an active pack name to its JSON file (packs_dir first, then REPO_ROOT/packs)."""
    filename = name if name.endswith(".json") else f"{name}.json"
    candidate = (packs_dir or PACKS_DIR) / filename
    return candidate if candidate.exists() else REPO_ROOT / "packs" / filename


def policy_digest(config_path: Optional[Path], packs_dir: Optional[Path] = None) -> str:
    """SHA-256 over the config file and every active pack file, in load order.

    install-hooks pins this value into the hook command. The engine recomputes it
    on every call and fails closed on mismatch, so an agent that rewrites
    guardrails.json or a pack between calls disables nothing: it blocks itself.
    """
    h = hashlib.sha256()
    config: dict = {}
    if config_path is not None and Path(config_path).exists():
        raw = Path(config_path).read_bytes()
        h.update(b"config\0" + raw + b"\0")
        config = json.loads(raw.decode("utf-8"))
    else:
        h.update(b"config\0<none>\0")
    for name in config.get("active_packs", DEFAULT_ACTIVE_PACKS):
        pack_file = resolve_pack_file(name, packs_dir)
        h.update(b"pack\0" + name.encode("utf-8") + b"\0")
        h.update(pack_file.read_bytes() if pack_file.exists() else b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


# Keys whose values name a filesystem path in Claude Code and common MCP filesystem tools.
PATH_FIELD_KEYS = ("file_path", "path", "notebook_path", "source", "destination", "paths")

MUTATING_TOOL_HINTS = ("write", "edit", "create", "move", "delete", "rename", "patch", "append")


def extract_path_fields(payload_obj: Any) -> List[str]:
    """Collect string values of path-like keys from a tool_input dict."""
    found: List[str] = []
    if isinstance(payload_obj, dict):
        for key in PATH_FIELD_KEYS:
            val = payload_obj.get(key)
            if isinstance(val, str):
                found.append(val)
            elif isinstance(val, list):
                found.extend(v for v in val if isinstance(v, str))
    return found


def _resolve_quietly(p: str) -> Path:
    try:
        return Path(os.path.expanduser(p)).resolve()
    except (OSError, RuntimeError):
        return Path(os.path.expanduser(p))


def extract_strings_from_payload(payload_obj: Any) -> List[str]:
    """Recursively extract all string values from JSON/dict/list payload."""
    results = []
    if isinstance(payload_obj, str):
        results.append(payload_obj)
    elif isinstance(payload_obj, dict):
        for v in payload_obj.values():
            results.extend(extract_strings_from_payload(v))
    elif isinstance(payload_obj, (list, tuple)):
        for item in payload_obj:
            results.extend(extract_strings_from_payload(item))
    return results


class DLPEngine:
    """Deterministic PreToolUse Inspection and Control Engine."""

    DEFAULT_ACTIVE_PACKS = DEFAULT_ACTIVE_PACKS

    DEFAULT_EXEC_TOOLS = (
        "bash",
        "exec",
        "process",
        "code_execution",
        "shell",
        "terminal",
        "command",
    )

    # Approval-gate key material: no tool may read or write these (P0-1). Shell
    # commands are matched on the literal name (a tripwire; globs get past it).
    PROTECTED_SECRET_NAMES = (
        ".agent-guardrails-secret",
        ".approval_receipt.json",
    )

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        config: Optional[dict] = None,
        packs_dir: Optional[Union[str, Path]] = None,
    ):
        self.config_path = Path(config_path) if config_path else None
        self.packs_dir = Path(packs_dir) if packs_dir else PACKS_DIR
        self.loaded_config_path: Optional[Path] = None
        self.config = config if config is not None else self._load_config()
        if config is None:
            self._verify_policy_pin()

        # Resolve audit log to absolute path
        log_setting = self.config.get("audit_log", "tool_audit.jsonl")
        audit_path = Path(os.environ.get("GUARDRAILS_AUDIT_LOG", log_setting))
        if not audit_path.is_absolute():
            # Relative paths in a config file are relative to that file, so a
            # project's config never writes into the guardrails install's ledger.
            base = self.loaded_config_path.parent if self.loaded_config_path else REPO_ROOT
            audit_path = (base / audit_path).resolve()
        self.audit_log_path = audit_path

        # Resolve receipt and secret paths
        self.receipt_path = Path(
            os.environ.get(
                "APPROVAL_GATE_RECEIPT_FILE",
                self.config.get("approval_receipt_path", REPO_ROOT / ".approval_receipt.json"),
            )
        )
        self.secret_path = Path(
            os.environ.get(
                "APPROVAL_GATE_SECRET_FILE",
                self.config.get("approval_secret_path", Path.home() / ".agent-guardrails-secret"),
            )
        )

        self.exec_tools = tuple(
            t.lower() for t in self.config.get("exec_tool_names", self.DEFAULT_EXEC_TOOLS)
        )
        self.outbound_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r"mcp__.*(?:buffer|gmail).*",
                r"^publish$",
                r"^send_email$",
                r"^post_status$",
                r"^outbound$",
            ]
        ]

        self.global_rules: List[dict] = []
        self.command_rules: List[dict] = []
        self.outbound_rules: List[dict] = []
        self.path_regex: Optional[re.Pattern] = None

        self._load_packs()
        self._load_denylisted_paths()
        self._load_term_denylist()

    def _load_config(self) -> dict:
        # Never read guardrails.json from the agent's working directory: the agent
        # can write there. Sources, in order: explicit path, GUARDRAILS_CONFIG
        # (set by the install-hooks command), the install's own guardrails.json.
        candidate_paths = []
        if self.config_path:
            candidate_paths.append(self.config_path)
        else:
            env_cfg = os.environ.get("GUARDRAILS_CONFIG")
            if env_cfg:
                env_path = Path(env_cfg)
                if not env_path.exists():
                    print(f"CRITICAL: GUARDRAILS_CONFIG points to a missing file: {env_path}", file=sys.stderr)
                    sys.exit(2)
                candidate_paths.append(env_path)
            candidate_paths.append(REPO_ROOT / "guardrails.json")

        for target in candidate_paths:
            if target.exists():
                try:
                    data = json.loads(target.read_text(encoding="utf-8"))
                except Exception as exc:
                    print(f"CRITICAL: Failed to parse guardrails config at {target}: {exc}", file=sys.stderr)
                    sys.exit(2)
                if not isinstance(data, dict):
                    print(f"CRITICAL: guardrails config at {target} is not a JSON object", file=sys.stderr)
                    sys.exit(2)
                self.loaded_config_path = target.resolve()
                return data
        return {}

    def _verify_policy_pin(self):
        """Fail closed if config or packs changed since install-hooks pinned them."""
        pinned = os.environ.get("GUARDRAILS_POLICY_SHA256")
        if not pinned:
            return
        try:
            actual = policy_digest(self.loaded_config_path, self.packs_dir)
        except Exception as exc:
            print(f"CRITICAL: could not hash guardrails policy: {exc}", file=sys.stderr)
            sys.exit(2)
        if actual != pinned:
            print(
                "CRITICAL: guardrails.json or a policy pack changed since install-hooks pinned it. "
                "If a human made this change, re-run `guardrails.py install-hooks`. Failing closed.",
                file=sys.stderr,
            )
            sys.exit(2)

    def _load_packs(self):
        active_pack_names = self.config.get("active_packs", self.DEFAULT_ACTIVE_PACKS)
        loaded_packs = set()

        for name in active_pack_names:
            pack_file = resolve_pack_file(name, self.packs_dir)

            if not pack_file.exists():
                # P1-2: Missing active pack fails closed
                print(f"CRITICAL: Active pack file not found: {pack_file.name}", file=sys.stderr)
                sys.exit(2)

            if pack_file not in loaded_packs:
                try:
                    data = json.loads(pack_file.read_text(encoding="utf-8"))
                    self._register_pack_rules(data.get("rules", []))
                    loaded_packs.add(pack_file)
                except Exception as exc:
                    print(f"CRITICAL: Failed to read pack {pack_file}: {exc}", file=sys.stderr)
                    sys.exit(2)

        if not self.global_rules and not self.command_rules:
            print("CRITICAL: No security rules loaded. Failing closed.", file=sys.stderr)
            sys.exit(2)

    def _register_pack_rules(self, rules: List[dict]):
        for r in rules:
            rule_id = r.get("id", "unnamed_rule")
            tier = r.get("tier", "global").lower()
            pattern_str = r.get("pattern", "")
            if not pattern_str:
                continue

            flags = re.IGNORECASE if (tier == "outbound" or "case_insensitive" in r) else 0
            try:
                compiled = re.compile(pattern_str, flags)
            except re.error as exc:
                print(f"CRITICAL: Invalid regex in rule {rule_id}: {exc}", file=sys.stderr)
                sys.exit(2)

            is_luhn = bool(r.get("luhn", False))
            action = r.get("action", "block")
            entry = {
                "id": rule_id,
                "tier": tier,
                "pattern": compiled,
                "description": r.get("description", ""),
                "action": action,
                "is_luhn": is_luhn,
            }

            if tier == "global":
                self.global_rules.append(entry)
            elif tier == "command":
                self.command_rules.append(entry)
            elif tier == "outbound":
                self.outbound_rules.append(entry)

    def _load_denylisted_paths(self):
        floor = [str(d).strip() for d in self.config.get("denylisted_dirs", []) if str(d).strip()]
        dirs = list(floor)

        registry_path = self.config.get("registry")
        if registry_path:
            reg = Path(registry_path)
            if not reg.is_absolute() and self.config_path:
                reg = self.config_path.parent / reg
            if reg.exists():
                try:
                    reg_data = json.loads(reg.read_text(encoding="utf-8"))
                    for d in reg_data.get("denylist", []):
                        d_str = str(d).strip()
                        if d_str and d_str not in dirs:
                            dirs.append(d_str)
                except Exception as exc:
                    print(f"CRITICAL: Failed to read denylist registry {reg}: {exc}", file=sys.stderr)
                    sys.exit(2)

        if dirs:
            self.path_regex = re.compile(
                r"[/~]\s*(?:" + "|".join(re.escape(d) for d in dirs) + r")(?:\b|/)",
                re.IGNORECASE,
            )

        self.secret_name_regex = re.compile(
            r"(?:^|[\s'\"`/~=])(?:" + "|".join(re.escape(p) for p in self.PROTECTED_SECRET_NAMES) + r")(?:\b|/|$)",
            re.IGNORECASE,
        )

    def _protected_file_violation(self, tool_lower: str, is_exec: bool, payload_obj: Any,
                                  candidates: List[str]) -> Optional[str]:
        """Return a reason if the call touches gate secrets or mutates guardrails policy."""
        if is_exec:
            # Shell: literal-name tripwire on the secret and receipt only. Policy
            # files are covered by the policy pin, so commit messages, greps and
            # docs that mention guardrails.json stay allowed.
            if any(self.secret_name_regex.search(c) for c in candidates):
                return "approval-gate secret or receipt"
            return None

        paths = [_resolve_quietly(p) for p in extract_path_fields(payload_obj)]
        if not paths:
            return None
        secret_files = {_resolve_quietly(str(self.secret_path)), _resolve_quietly(str(self.receipt_path))}
        for p in paths:
            if p in secret_files or p.name in self.PROTECTED_SECRET_NAMES:
                return "approval-gate secret or receipt"

        if not any(h in tool_lower for h in MUTATING_TOOL_HINTS):
            return None  # reading policy and source files is fine
        protected_dirs = (REPO_ROOT.resolve() / "packs", REPO_ROOT.resolve() / "src")
        for p in paths:
            if p.name == "guardrails.json" or p == self.loaded_config_path:
                return "guardrails policy config"
            if any(p == d or d in p.parents for d in protected_dirs):
                return "guardrails policy pack or engine source"
            if ".claude" in p.parts and p.name.startswith("settings") and p.suffix == ".json":
                return "harness settings (hook registration)"
        return None

    def _load_term_denylist(self):
        term_files = self.config.get("term_denylist_files", ["dlp_denylist.local.txt"])
        terms = []
        for tf in term_files:
            p = Path(tf)
            if not p.is_absolute() and self.config_path:
                p = self.config_path.parent / p
            elif not p.is_absolute():
                p = REPO_ROOT / p
            if p.exists():
                try:
                    lines = [
                        line.strip()
                        for line in p.read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    terms.extend(lines)
                except OSError:
                    continue
        if terms:
            self.global_rules.append({
                "id": "term_denylist",
                "tier": "global",
                "pattern": re.compile(r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b", re.IGNORECASE),
                "description": "Local proprietary terms denylist",
                "action": "block",
                "is_luhn": False,
            })

    def check(
        self,
        payload_input: Union[str, dict, list],
        tool_name: str = "Bash",
        check_approval: bool = True,
    ) -> Optional[dict]:
        """Inspect a tool call payload against all configured tiers.

        Returns None if allowed, or a dict describing the block reason.
        """
        tool_lower = tool_name.strip().lower()
        is_exec = tool_lower in self.exec_tools or any(tool_lower.endswith(x) for x in self.exec_tools)
        is_outbound = any(p.search(tool_name) for p in self.outbound_patterns)

        # P1-1: Extract raw strings and build normalized candidate strings
        payload_obj: Any = payload_input
        if isinstance(payload_input, str):
            raw_strings = [payload_input]
            try:
                payload_obj = json.loads(payload_input)
                raw_strings.extend(extract_strings_from_payload(payload_obj))
            except Exception:
                payload_obj = None
        else:
            raw_strings = extract_strings_from_payload(payload_input)
            raw_strings.append(json.dumps(payload_input, ensure_ascii=False))

        normalized_strings = [normalize_command_text(s) for s in raw_strings]
        all_candidate_strings = list(set(raw_strings + normalized_strings))

        # ── 1. GLOBAL TIER ──
        for candidate in all_candidate_strings:
            for rule in self.global_rules:
                pattern = rule["pattern"]
                if rule["is_luhn"]:
                    # P1-7: Check EVERY candidate match via finditer
                    for m in pattern.finditer(candidate):
                        matched_text = m.group(0)
                        digits = re.sub(r"[ -]", "", matched_text)
                        if luhn_valid(digits):
                            self._record_block(tool_name, rule["id"], rule["tier"], rule["description"])
                            return {
                                "tier": rule["tier"],
                                "rule_id": rule["id"],
                                "action": rule["action"],
                                "description": rule["description"],
                                "matched": rule["id"],
                            }
                else:
                    if pattern.search(candidate):
                        self._record_block(tool_name, rule["id"], rule["tier"], rule["description"])
                        return {
                            "tier": rule["tier"],
                            "rule_id": rule["id"],
                            "action": rule["action"],
                            "description": rule["description"],
                            "matched": rule["id"],
                        }

        # ── 2. PATH TIER ──
        protected = self._protected_file_violation(tool_lower, is_exec, payload_obj, all_candidate_strings)
        if protected:
            desc = f"Attempted access to protected file: {protected}"
            self._record_block(tool_name, "protected_guardrails_file", "path", desc)
            return {
                "tier": "path",
                "rule_id": "protected_guardrails_file",
                "action": "block",
                "description": desc,
                "matched": "protected_guardrails_file",
            }

        if self.path_regex is not None:
            for candidate in all_candidate_strings:
                if self.path_regex.search(candidate) or self.path_regex.search(defang_shell_quoting(candidate)):
                    desc = "Attempted access to sensitive denylisted path"
                    self._record_block(tool_name, "denylisted_path", "path", desc)
                    return {
                        "tier": "path",
                        "rule_id": "denylisted_path",
                        "action": "block",
                        "description": desc,
                        "matched": "denylisted_path",
                    }

        # ── 3. COMMAND TIER (Exec Tools Only) ──
        if is_exec:
            approved_scopes = set()
            for candidate in all_candidate_strings:
                for rule in self.command_rules:
                    rule_id = rule["id"]
                    if not rule["pattern"].search(candidate):
                        continue

                    # P0-2: Require explicit action == "require_approval"
                    if rule.get("action") == "require_approval":
                        if rule_id in approved_scopes:
                            continue  # Already verified for this invocation

                        if check_approval:
                            is_valid, reason = verify_receipt(
                                scope=rule_id,
                                receipt_path=self.receipt_path,
                                secret_path=self.secret_path,
                                consume=True,
                            )
                            if is_valid:
                                approved_scopes.add(rule_id)
                                continue  # Clearance granted for THIS rule; CONTINUE checking remaining rules!

                        desc = f"Action '{rule_id}' requires terminal HMAC human clearance"
                        self._record_block(tool_name, f"approval_required_{rule_id}", "command", desc)
                        return {
                            "tier": "command",
                            "rule_id": f"approval_required_{rule_id}",
                            "action": "require_approval",
                            "description": desc,
                            "matched": rule_id,
                        }

                    # Hard block rule (e.g. git_force_push, rm_rf_critical, terraform_destroy)
                    self._record_block(tool_name, rule["id"], rule["tier"], rule["description"])
                    return {
                        "tier": rule["tier"],
                        "rule_id": rule["id"],
                        "action": rule["action"],
                        "description": rule["description"],
                        "matched": rule["id"],
                    }

        # ── 4. OUTBOUND TIER (Publishing Tools Only) ──
        if is_outbound:
            for candidate in all_candidate_strings:
                for rule in self.outbound_rules:
                    if rule["pattern"].search(candidate):
                        self._record_block(tool_name, rule["id"], rule["tier"], rule["description"])
                        return {
                            "tier": rule["tier"],
                            "rule_id": rule["id"],
                            "action": rule["action"],
                            "description": rule["description"],
                            "matched": rule["id"],
                        }

        return None

    def _record_block(self, tool_name: str, rule_id: str, tier: str, description: str):
        details = f"BLOCKED: rule='{rule_id}', tier='{tier}', desc='{description}'"
        try:
            log_tool_action(
                tool_name=tool_name,
                status="BLOCKED",
                details=details,
                log_path=self.audit_log_path,
            )
        except Exception:
            pass


_DEFAULT_ENGINE: Optional[DLPEngine] = None


def get_default_engine() -> DLPEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = DLPEngine()
    return _DEFAULT_ENGINE


def check_dlp(text: str, outbound: bool, is_exec: bool = False) -> Optional[str]:
    """Compatibility wrapper matching legacy check_dlp signature."""
    engine = get_default_engine()
    tool_name = "mcp__claude_ai_Buffer__post" if outbound else ("Bash" if is_exec else "Write")
    res = engine.check(text, tool_name=tool_name, check_approval=False)
    if res:
        if res["tier"] == "outbound":
            return f"outbound:{res['rule_id']}"
        return res["rule_id"]
    return None


def evaluate_tool_call(raw_input_text: str) -> Tuple[int, str]:
    """Process a tool call payload and return (exit_code, message)."""
    if not raw_input_text.strip():
        return 0, "Empty payload allowed"

    try:
        data = json.loads(raw_input_text)
    except Exception:
        data = {"raw_text": raw_input_text}

    tool_name = str(data.get("tool_name") or data.get("tool", "Bash"))
    tool_input = data.get("tool_input", data)

    engine = get_default_engine()
    block = engine.check(tool_input, tool_name=tool_name, check_approval=True)

    if block:
        msg = (
            f"BLOCKED by DLP PreToolUse hook: rule '{block['rule_id']}' matched in payload "
            f"(tool={tool_name}, tier={block['tier']}). {block['description']}"
        )
        return 2, msg

    return 0, "ALLOWED"


def main():
    try:
        raw_input = sys.stdin.read()
        code, msg = evaluate_tool_call(raw_input)
        if code != 0:
            print(msg, file=sys.stderr)
            sys.exit(code)
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        # P1-4: ALWAYS exit 2 on any crash or internal exception
        print(
            f"BLOCKED by DLP PreToolUse hook: internal exception ({type(exc).__name__}: {exc}); "
            "failing closed.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()

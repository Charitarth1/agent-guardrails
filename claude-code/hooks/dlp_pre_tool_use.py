#!/usr/bin/env python3
"""
DLP PreToolUse hook for Claude Code (and any agent runtime that can call a
command hook with the tool call as JSON on stdin).

Exit code 2 blocks the tool call (Claude Code PreToolUse contract); 0 allows it.

Four tiers, chosen so legitimate work is not blocked (a hook that blocks real
work gets switched off, and then it protects nothing):

  GLOBAL   every matched tool call. Credentials and private keys, Luhn-valid
           payment card numbers, Luhn-valid 9-digit IDs (e.g. Canadian SIN),
           separator-format SSNs, and your own term denylist (client names,
           codenames, personal literals).
  PATH     every matched tool call. Denylisted directories in path-shaped
           position only, so prose that merely names a directory still passes.
           Matched against the raw text and a quote-stripped copy (F-16).
  COMMAND  exec-like tools only. Credential paths, keychain reads, remote
           pushes, and network exfiltration. A command string is an action;
           the same words in a document are subject matter.
  OUTBOUND publishing tools only (e.g. a social or email MCP). Broader
           personal-context keywords: personal finance, medical, dating,
           housing.

Configuration comes from guardrails.json next to this file, or from the path
in $GUARDRAILS_CONFIG. See guardrails.example.json.

Known limits (see docs/limitations.md): this is a pattern matcher. It is a
tripwire and an audit point, not a sandbox. Globs (cat ~/vault*/x), shell
variables, base64, and interpreters (python -c) can reach a denylisted path
without naming it. Pair it with harness deny rules and OS-level isolation.

The F-numbers in comments refer to findings in docs/lessons-from-a-self-audit.md.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("GUARDRAILS_CONFIG", HERE / "guardrails.json"))


def _load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[dlp] WARNING: no config at {CONFIG_PATH}; PATH tier and term "
              "denylist are empty. Copy guardrails.example.json.", file=sys.stderr)
    except Exception as exc:
        print(f"[dlp] WARNING: unreadable config {CONFIG_PATH} ({exc}); "
              "PATH tier and term denylist are empty.", file=sys.stderr)
    return {}


CONFIG = _load_config()


def _resolve(p):
    p = Path(os.path.expanduser(str(p)))
    return p if p.is_absolute() else CONFIG_PATH.parent / p


AUDIT_LOG_FILE = _resolve(os.environ.get("GUARDRAILS_AUDIT_LOG",
                                         CONFIG.get("audit_log", "tool_audit.jsonl")))
TERM_FILES = [_resolve(p) for p in CONFIG.get("term_denylist_files", ["dlp_denylist.local.txt"])]
REGISTRY = _resolve(CONFIG["registry"]) if CONFIG.get("registry") else None

# Tools that publish beyond the local filesystem: the OUTBOUND tier applies.
OUTBOUND_TOOL_PREFIXES = tuple(CONFIG.get("outbound_tool_prefixes", [
    "mcp__claude_ai_Buffer__",
    "mcp__claude_ai_Gmail__",
]))

# Tools that execute commands: the COMMAND tier applies.
EXEC_TOOL_NAMES = tuple(n.lower() for n in CONFIG.get("exec_tool_names", [
    "bash", "exec", "process", "code_execution", "shell",
]))

# The floor of denylisted directories. A registry (any JSON file with a
# "denylist" list) can ADD to it but never remove from it (F-5).
DENYLIST_FLOOR = [str(d) for d in CONFIG.get("denylisted_dirs", []) if str(d).strip()]

# ─── GLOBAL tier: high-confidence patterns, near-zero false-positive rate ───

GLOBAL_PATTERNS = {
    "secrets_credentials": re.compile(
        r"(?:ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,}"
        r"|sk_live_[0-9a-zA-Z]{24,99}|sk-ant-[0-9a-zA-Z\-_]{20,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)"
    ),
    # US SSN: separator format required. Bare 9-digit numbers are everywhere
    # in financial models, invoices, and token counts.
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

# Candidate digit runs checked with Luhn (cards 13-19 digits, SIN exactly 9).
CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SIN_CANDIDATE = re.compile(r"\b\d{3}[ -]\d{3}[ -]\d{3}\b|\b\d{9}\b")

# ─── OUTBOUND tier: personal-context keywords, publishing tools only ───

OUTBOUND_PATTERNS = {
    "financial_personal": re.compile(
        r"\b(?:account number|routing number|cvv|iban|tax return|salary|rrsp|tfsa|mortgage)\b",
        re.IGNORECASE,
    ),
    "medical": re.compile(
        r"\b(?:diagnosis|prescription|medication|therapy session|psychiatrist|dosage|pathology)\b",
        re.IGNORECASE,
    ),
    "intimate": re.compile(
        r"\b(?:tinder|bumble|hinge|romantic partner|dating app)\b",
        re.IGNORECASE,
    ),
    "housing_address": re.compile(
        r"\b(?:rental agreement|month-to-month|tenant|landlord|lease agreement|residential tenancy)\b",
        re.IGNORECASE,
    ),
}


# ─── PATH tier: denylisted directories, every tool (F-10) ───

def _load_denylisted_dirs():
    """Union of the floor and the registry, never one or the other (F-5).

    Returning the registry alone lets an edit shrink coverage; returning the
    floor alone on a read failure lets coverage go stale. The union means
    neither a missing registry nor an edited one can remove a directory.
    """
    dirs = list(DENYLIST_FLOOR)
    if REGISTRY is None:
        return dirs
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
        registry = data.get("denylist")
        if isinstance(registry, list):
            for d in registry:
                if str(d).strip() and str(d) not in dirs:
                    dirs.append(str(d))
    except Exception:
        # Say so. A silent degrade here is how F-5 stayed invisible.
        print(f"[dlp] WARNING: could not read registry {REGISTRY}; "
              "PATH tier is using the floor only.", file=sys.stderr)
    return dirs


def _build_path_re(dirs):
    if not dirs:
        return None
    return re.compile(
        r"[/~]\s*(?:" + "|".join(re.escape(d) for d in dirs) + r")(?:\b|/)",
        re.IGNORECASE,
    )


DENYLISTED_PATH_RE = _build_path_re(_load_denylisted_dirs())

# ─── COMMAND tier: credential access and exfiltration, exec-like tools only ───

COMMAND_PATTERNS = {
    "cmd_ssh_credentials": re.compile(
        r"(?:^|[\s'\"`/~=])\.ssh(?:\b|/)|\bid_rsa\b|\bid_ed25519\b"
    ),
    "cmd_cloud_credentials": re.compile(
        r"(?:^|[\s'\"`/~=])\.aws(?:\b|/)|application_default_credentials"
        r"|\bcredentials\.json\b|\bserviceAccount\w*\.json\b"
    ),
    "cmd_dotenv_access": re.compile(r"(?:^|[\s'\"`/~=])\.env(?:\b|\.)"),
    "cmd_gh_hosts": re.compile(r"gh/hosts\.yml"),
    "cmd_keychain": re.compile(r"\bsecurity\s+find-(?:generic|internet)-password\b"),
    "cmd_remote_push": re.compile(r"\bgit\s+push\b|\bgit\s+remote\s+add\b"),
    "cmd_exfiltration": re.compile(
        r"\b(?:curl|wget)\s+[^|;]*https?://|\bnc\s+-|/dev/tcp/"
    ),
}


def _load_term_denylist():
    """Client names and personal literals: GLOBAL tier, never in any file."""
    terms = []
    for path in TERM_FILES:
        try:
            if path.exists():
                terms += [
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
        except OSError:
            continue
    if terms:
        GLOBAL_PATTERNS["term_denylist"] = re.compile(
            r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b",
            re.IGNORECASE,
        )


_load_term_denylist()


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
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


def _defang_shell_quoting(text: str) -> str:
    """Strip shell quoting so quoting a directory name cannot evade the PATH
    tier (F-16). The shell resolves all of these to the same path:

        cat ~/Projects/'private-vault'/keys.txt
        cat ~/Projects/"private-vault"/keys.txt
        cat ~/Projects/Finance\\ Records/x.csv

    The original text is matched first, so nothing caught before is lost.
    """
    return text.replace("'", "").replace('"', "").replace("\\ ", " ").replace("\\", "")


def check_dlp(text: str, outbound: bool, is_exec: bool = False):
    """Return the matched category on a hit, else None."""
    for category, pattern in GLOBAL_PATTERNS.items():
        if pattern.search(text):
            return category

    if DENYLISTED_PATH_RE is not None and (
        DENYLISTED_PATH_RE.search(text) or DENYLISTED_PATH_RE.search(_defang_shell_quoting(text))
    ):
        return "denylisted_path"

    if is_exec:
        for category, pattern in COMMAND_PATTERNS.items():
            if pattern.search(text):
                return category

    for m in CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            return "payment_card_luhn"
    for m in SIN_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if len(digits) == 9 and luhn_valid(digits):
            return "sin_luhn"

    if outbound:
        for category, pattern in OUTBOUND_PATTERNS.items():
            if pattern.search(text):
                return f"outbound:{category}"
    return None


def log_audit_record(tool_name: str, status: str, details: str):
    """Append-only JSONL. Never logs the payload itself, only what matched."""
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cwd": os.getcwd(),
            "hook": "PreToolUse-DLP",
            "tool": tool_name,
            "status": status,
            "details": details,
        }
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as exc:
        # Logging must never turn a block into an allow.
        print(f"[dlp] WARNING: audit log write failed ({exc})", file=sys.stderr)


def main():
    raw_input_text = sys.stdin.read()
    if not raw_input_text.strip():
        sys.exit(0)

    try:
        data = json.loads(raw_input_text)
    except Exception:
        data = {"raw_text": raw_input_text}

    tool_name = data.get("tool_name") or data.get("tool", "unknown_tool")
    outbound = str(tool_name).startswith(OUTBOUND_TOOL_PREFIXES)
    is_exec = str(tool_name).strip().lower() in EXEC_TOOL_NAMES
    payload_str = json.dumps(data.get("tool_input", data), ensure_ascii=False)

    matched = check_dlp(payload_str, outbound=outbound, is_exec=is_exec)
    if matched:
        if matched.startswith("outbound:"):
            tier = "outbound"
        elif matched.startswith("cmd_"):
            tier = "command"
        elif matched == "denylisted_path":
            tier = "path"
        else:
            tier = "global"
        msg = (f"BLOCKED by DLP PreToolUse hook: pattern '{matched}' matched in payload "
               f"(tool={tool_name}, tier={tier}).")
        log_audit_record(tool_name, "BLOCKED", msg)
        print(msg, file=sys.stderr)
        sys.exit(2)

    # Allowed calls are logged by the PostToolUse audit hook; stay quiet here
    # to avoid double-logging every write.
    sys.exit(0)


if __name__ == "__main__":
    # Claude Code only blocks on exit code 2. An uncaught exception exits 1,
    # which lets the tool call through, so a crash here must fail closed.
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print(f"BLOCKED by DLP PreToolUse hook: internal error ({type(exc).__name__}); "
              "failing closed.", file=sys.stderr)
        sys.exit(2)

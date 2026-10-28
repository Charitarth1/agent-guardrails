#!/usr/bin/env python3
"""src/audit_post_tool_use.py — SHA-256 Hash-Chained Audit Log (detects naive edits only).

Enforces:
1. Append-only logging with sequential numbering and SHA-256 hash chaining (prev_hash -> entry_hash).
2. Concurrency safety: atomic file locking via fcntl.flock to prevent chain forking under parallel tool calls.
3. Sensitive data redaction: scrubs database passwords, flags (-p, --password), and API keys before logging.
4. Tamper verification utility (--verify) that detects line deletions, insertions, or naive payload modifications.

Standard library only. Compatible with Python 3.9+.
"""

import fcntl
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_LOG = REPO_ROOT / "tool_audit.jsonl"


def redact_sensitive_content(text: str) -> str:
    """Scrub passwords, credentials, and authentication tokens before logging."""
    t = re.sub(r"-p[^\s]+", "-p[REDACTED]", text)
    t = re.sub(r"--password(?:=|\s+)[^\s]+", "--password=[REDACTED]", t)
    t = re.sub(r"(?:api[-_]?key|token|secret|password|bearer)[=:\s]+[^\s]+", "[REDACTED]", t, flags=re.IGNORECASE)
    return t


def _canonical_bytes(record: dict) -> bytes:
    """Produce deterministic byte representation for hashing."""
    filtered = {k: v for k, v in record.items() if k != "entry_hash"}
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False).encode("utf-8")


def log_tool_action(
    tool_name: str,
    status: str,
    details: str,
    log_path: Optional[Path] = None,
    cwd: Optional[str] = None,
) -> dict:
    """Append a hash-chained audit record under an exclusive file lock."""
    target_path = Path(log_path or os.environ.get("GUARDRAILS_AUDIT_LOG", DEFAULT_LOG)).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_path, "a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            lines = [line.strip() for line in f if line.strip()]
            prev_hash = "GENESIS"
            if lines:
                try:
                    last_record = json.loads(lines[-1])
                    prev_hash = last_record.get("entry_hash", "GENESIS")
                except Exception:
                    pass

            now_iso = datetime.now(timezone.utc).isoformat()
            safe_details = redact_sensitive_content(details)

            record = {
                "seq": len(lines) + 1,
                "timestamp": now_iso,
                "cwd": cwd or os.getcwd(),
                "tool": tool_name,
                "status": status,
                "details": safe_details,
                "prev_hash": prev_hash,
            }

            entry_hash = hashlib.sha256(_canonical_bytes(record)).hexdigest()
            record["entry_hash"] = entry_hash

            f.seek(0, os.SEEK_END)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    return record


def verify_audit_log(log_path: Optional[Path] = None) -> Tuple[bool, str, int]:
    """Verify unbroken SHA-256 hash chaining and sequence continuity.

    Returns (is_valid, reason, line_number_or_count).
    """
    target_path = Path(log_path or os.environ.get("GUARDRAILS_AUDIT_LOG", DEFAULT_LOG)).resolve()
    if not target_path.exists():
        return True, "log_empty_or_missing", 0

    with open(target_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        return True, "log_empty", 0

    expected_prev = "GENESIS"
    expected_seq = 1
    for idx, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except Exception:
            return False, "json_parse_error", idx

        recorded_hash = record.get("entry_hash", "")
        recorded_prev = record.get("prev_hash", "")
        recorded_seq = record.get("seq")

        # 1. Check sequence number if present
        if recorded_seq is not None and recorded_seq != expected_seq:
            return False, f"sequence_gap (expected seq {expected_seq}, got {recorded_seq})", idx

        # 2. Check chain continuity
        if recorded_prev != expected_prev:
            return False, f"chain_broken (expected prev_hash '{expected_prev[:8]}...', got '{recorded_prev[:8]}...')", idx

        # 3. Check record integrity
        computed_hash = hashlib.sha256(_canonical_bytes(record)).hexdigest()
        if computed_hash != recorded_hash:
            return False, f"hash_mismatch (computed '{computed_hash[:8]}...', recorded '{recorded_hash[:8]}...')", idx

        expected_prev = recorded_hash
        expected_seq += 1

    return True, "valid", len(lines)


def _extract_target(data: dict) -> str:
    tool_input = data.get("tool_input", {})
    if isinstance(tool_input, str):
        return redact_sensitive_content(tool_input[:100])
    if isinstance(tool_input, dict):
        for k in ("command", "path", "file_path", "url", "target"):
            if k in tool_input:
                raw_val = str(tool_input[k])[:80]
                return f"{k}: {redact_sensitive_content(raw_val)}"
    return "executed"


def main():
    if "--verify" in sys.argv:
        target = None
        if len(sys.argv) > 2 and sys.argv[2] != "--verify":
            target = Path(sys.argv[2])
        valid, reason, count = verify_audit_log(target)
        if valid:
            print(f"[audit] VALID: Chain intact across {count} entry(s).")
            sys.exit(0)
        else:
            print(f"[audit] INVALID: {reason} at record {count}", file=sys.stderr)
            sys.exit(1)

    raw_input_text = sys.stdin.read()
    if not raw_input_text.strip():
        sys.exit(0)

    try:
        data = json.loads(raw_input_text)
    except Exception:
        data = {"raw_text": raw_input_text}

    tool_name = str(data.get("tool_name") or data.get("tool", "unknown_tool"))
    target = _extract_target(data)

    log_tool_action(
        tool_name=tool_name,
        status="ALLOWED",
        details=f"Target: {target}",
    )
    sys.exit(0)


if __name__ == "__main__":
    main()

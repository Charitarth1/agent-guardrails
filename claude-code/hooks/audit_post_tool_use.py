#!/usr/bin/env python3
"""
Audit-log PostToolUse hook. Appends one JSONL record per executed tool call.

Supports record-keeping duties such as NIST AI RMF MEASURE 2.6 and EU AI Act
Art. 12 (automatic logging). The log is append-only by convention, not
tamper-proof: ship it somewhere you can't edit from the agent's account if
you need integrity (see docs/limitations.md).

Records the tool and target, never the content or the output, so the audit
log does not become a second copy of whatever sensitive data passed through.

Log path: "audit_log" in guardrails.json, or $GUARDRAILS_AUDIT_LOG.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("GUARDRAILS_CONFIG", HERE / "guardrails.json"))


def _audit_log_path():
    configured = "tool_audit.jsonl"
    try:
        configured = json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("audit_log", configured)
    except Exception:
        pass
    p = Path(os.path.expanduser(os.environ.get("GUARDRAILS_AUDIT_LOG", configured)))
    return p if p.is_absolute() else CONFIG_PATH.parent / p


def main():
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        return

    try:
        data = json.loads(raw_input)
    except Exception:
        data = {}

    tool_name = data.get("tool_name") or data.get("tool", "unknown_tool")
    tool_input = data.get("tool_input") or data.get("input", {})

    target = ""
    if isinstance(tool_input, dict):
        target = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("url") or ""

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cwd": os.getcwd(),
        "tool": tool_name,
        "target_path": target,
        "status": "ALLOWED_EXECUTED",
        "compliance_map": ["NIST-AI-RMF-MEASURE-2.6", "EU-AI-ACT-ART-12"],
    }
    log = _audit_log_path()
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    # PostToolUse runs after the call, so it cannot block anything. Never let a
    # logging failure surface as a tool error.
    try:
        main()
    except Exception as exc:
        print(f"[audit] WARNING: could not write audit record ({exc})", file=sys.stderr)
    sys.exit(0)

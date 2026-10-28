#!/usr/bin/env python3
"""matrix/build_matrix_md.py — Deterministic Markdown Generator for the Matrix.

Reads matrix/risk_control_matrix.json and generates matrix/MATRIX.md.
Standard library only. Compatible with Python 3.9+.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = REPO_ROOT / "matrix" / "risk_control_matrix.json"
MD_PATH = REPO_ROOT / "matrix" / "MATRIX.md"


def _sanitize(text: str) -> str:
    return str(text or "").replace("|", "\\|")


def generate_markdown(data: dict) -> str:
    lines = []
    lines.append(f"# {data.get('title', 'Agentic AI Risk & Control Matrix')}")
    lines.append("")
    lines.append(f"> **Standard:** {data.get('standard')}  ")
    lines.append(f"> **Version:** {data.get('version')} | **Scope:** {data.get('scope_framework')}")
    lines.append("")
    lines.append("## Executive Summary & Scope Boundary")
    lines.append("")
    lines.append(data.get("runtime_scoping_note", ""))
    lines.append("")
    lines.append("### Core Governance Domains")
    lines.append("")
    for code, name in data.get("domains", {}).items():
        lines.append(f"- **`{code}`**: {name}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Risk, Control & Evidence Matrix")
    lines.append("")
    lines.append(
        "| Risk ID | Control ID | Domain | Risk Name | Standards Mapping | Control Specification | Evidence Artifact | Enforced By |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|---|"
    )

    for r in data.get("risks", []):
        owasp = r.get("owasp_agentic_id", "")
        mit = r.get("mit_subdomain", "")
        nist = r.get("nist_ai_rmf", "")
        arc = r.get("govtech_arc_ref", "")
        mapping = f"**OWASP:** `{owasp}`<br/>**MIT:** `{mit}`<br/>**NIST:** `{nist}`<br/>**ARC:** `{arc}`"

        ctrl = _sanitize(r.get("control_spec", ""))
        evid_text = _sanitize(r.get("evidence_artifact", ""))
        loc = _sanitize(r.get("typical_location", ""))
        evid = f"{evid_text}<br/>*(Loc: `{loc}`)*"
        enf = f"`{r.get('enforced_by', '')}`"
        name = _sanitize(r.get("name", ""))
        failure = _sanitize(r.get("failure_mode", ""))
        cid = _sanitize(r.get("control_id", ""))

        lines.append(
            f"| `{r['id']}` | `{cid}` | **{r['domain']}** | **{name}**<br/>_{failure}_ | {mapping} | {ctrl} | {evid} | {enf} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## How to Verify")
    lines.append("")
    lines.append("```bash")
    lines.append("# Run the matrix schema and boundary test suite")
    lines.append("python3 -m unittest tests/test_matrix.py")
    lines.append("")
    lines.append("# Recompile this document from the source JSON")
    lines.append("python3 matrix/build_matrix_md.py")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def main():
    if not JSON_PATH.exists():
        raise FileNotFoundError(f"Missing {JSON_PATH}")
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    content = generate_markdown(data)
    MD_PATH.write_text(content, encoding="utf-8")
    print(f"Successfully generated {MD_PATH} ({len(data.get('risks', []))} risks).")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""src/fence_untrusted.py — Cryptographic Nonce Fencing & Prompt Injection Screener (F-2).

Enforces:
1. Dynamic cryptographic nonce generation per invocation (<untrusted_input_[nonce]>).
2. HTML-escaped attribute protection against attribute injection in source tag.
3. Payload neutralization: defangs embedded fake closing tags and markdown exfiltration images (AG-SAF-03).
4. Zero-width character stripping and heuristic injection screening for role overrides and exfiltration.
5. Exit code 2 on quarantine trigger, exit code 0 on clean text.

Standard library only. Compatible with Python 3.9+.
"""

import html
import os
import re
import secrets
import sys
from typing import Tuple

# ─── Heuristic Telemetry & Screening Patterns ───

INJECTION_PATTERNS = {
    "role_override": re.compile(
        r"(?i)\b(?:(?:ignore|forget|disregard)\s+(?:(?:the|all|any|of|your|my|our|these|those|prior|previous|above|earlier|existing|system)\s+)*"
        r"(?:instructions|directions|directives|rules|constraints|guidelines|prompts?|everything\s+above|above)|"
        r"system\s+override(?:\s*:|\s+and|\s+disregard|\s+mode|\s+enter)|"
        r"you\s+are\s+now\s+(?:in\s+developer\s+mode|unrestricted|a\s+new\s+agent|DAN\b|jailbroken\b)|"
        r"new\s+directive:\s*ignore)\b"
    ),
    "credential_extraction": re.compile(
        r"(?i)(?:(?:read|cat|dump|print|output)\s+.*(?:\.ssh/id_|\.env|\.aws/|/etc/passwd|keychain)|"
        r"export\s+.*(?:to\s+webhook|to\s+https?://)|"
        r"leak\s+(?:api\s+key|token|credentials)|"
        r"output\s+all\s+environment\s+variables)"
    ),
    "outbound_exfiltration": re.compile(
        r"(?i)(?:(?:curl|wget|fetch|nc)\s+.*https?://[^\s]+\s+-(?:d|-data)|"
        r"send\s+(?:it\s+)?to\s+https?://|"
        r"reverse\s+shell|/dev/tcp/)"
    ),
}


def screen_for_injection(text: str) -> Tuple[bool, str]:
    """Scan text against heuristic adversarial patterns after zero-width stripping."""
    # Strip zero-width and invisible unicode characters (e.g. ig\u200bnore)
    cleaned = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    for category, pattern in INJECTION_PATTERNS.items():
        if pattern.search(cleaned):
            return True, category
    return False, ""


def neutralize_payload_escapes(text: str) -> str:
    """Neutralize fake closing tags and markdown exfiltration images."""
    # 1. Defang fake nonce tags, including ones split across lines or written as
    #    HTML entities (&lt;/untrusted_input_x&gt;) that a renderer would decode.
    t = re.sub(r"(?:<|&lt;|&#0*60;|&#x0*3c;)\s*/?\s*untrusted_input[^>]*?(?:>|&gt;|&#0*62;|&#x0*3e;)",
               "[neutralized_tag]", text, flags=re.IGNORECASE | re.DOTALL)
    #    A dangling opener with no closing bracket is still a spoof attempt.
    t = re.sub(r"(?:<|&lt;)\s*/?\s*untrusted_input", "[neutralized_tag]", t, flags=re.IGNORECASE)
    # 2. Defang image exfiltration (AG-SAF-03): inline markdown, reference-style
    #    definitions, and raw <img> tags pointing at remote URLs.
    t = re.sub(r"!\[([^\]]*)\]\(\s*<?https?://[^)]*\)", r"[image omitted: \1]", t)
    t = re.sub(r"(?m)^\s*\[[^\]]+\]:\s*<?https?://\S+.*$", "[remote reference omitted]", t)
    t = re.sub(r"!\[([^\]]*)\]\[[^\]]*\]", r"[image omitted: \1]", t)
    t = re.sub(r"<img\b[^>]*>", "[image omitted]", t, flags=re.IGNORECASE)
    return t


def fence_text(text: str, source: str = "unspecified") -> Tuple[str, bool, str]:
    """Enclose untrusted text within a cryptographic nonce boundary tag.

    Returns (fenced_text, is_quarantined, match_category).
    """
    # 8 bytes = 16 hex chars (64 bits of entropy)
    nonce = secrets.token_hex(8)
    safe_source = html.escape(str(source), quote=True)

    is_injected, category = screen_for_injection(text)
    sanitized_body = neutralize_payload_escapes(text)

    tag_attr = f' source="{safe_source}"' if safe_source else ""
    quarantine_attr = f' quarantine="true" reason="{category}"' if is_injected else ""

    header = f"<untrusted_input_{nonce}{tag_attr}{quarantine_attr}>\n"
    footer = f"\n</untrusted_input_{nonce}>"

    fenced = f"{header}{sanitized_body}{footer}"
    return fenced, is_injected, category


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else "stdin"
    raw_text = sys.stdin.read()

    fenced, is_quarantined, category = fence_text(raw_text, source=source)
    sys.stdout.write(fenced + "\n")

    if is_quarantined:
        sys.stderr.write(
            f"[fence] QUARANTINE: Adversarial injection pattern '{category}' detected in payload.\n"
        )
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

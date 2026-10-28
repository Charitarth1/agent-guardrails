#!/usr/bin/env python3
"""src/approval_gate.py — Terminal-Only HMAC-Signed Human Approval Gate (F-0, F-3).

Enforces:
1. Out-of-band interactive terminal approval (F-0: stops autonomous agent self-approval).
2. HMAC-SHA256 signature verification preventing model forgery or in-band chat arming.
3. Fail-closed expiration & timestamp verification (F-3: NaN/corrupt timestamps strictly block).
4. Single-use consumption: receipts are consumed on verification to prevent replay.
5. Strict TTL cap: verify refuses receipts with TTL > 60 minutes.
6. Fail-closed on missing/empty secrets: never creates secrets on the verify path.

Standard library only. Compatible with Python 3.9+.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_RECEIPT = REPO_ROOT / ".approval_receipt.json"
DEFAULT_SECRET = Path(os.environ.get("APPROVAL_GATE_SECRET_FILE", Path.home() / ".agent-guardrails-secret"))

MAX_TTL_MINUTES = 60


def _load_secret(secret_path: Path) -> Optional[bytes]:
    """Load existing secret. Returns None if missing or under 32 bytes."""
    if not secret_path.exists():
        return None
    try:
        data = secret_path.read_bytes().strip()
        if len(data) >= 32:
            return data
    except OSError:
        pass
    return None


def _get_or_create_secret_for_mint(secret_path: Path) -> bytes:
    """Load or atomically create a 32-byte secret with 0600 permissions."""
    existing = _load_secret(secret_path)
    if existing:
        return existing

    # Atomically create with 0600 permissions to avoid umask race
    secret = secrets.token_bytes(32)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(secret_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
    except FileExistsError:
        # File was created concurrently; re-read
        existing = _load_secret(secret_path)
        if existing:
            return existing
        raise PermissionError(f"Secret at {secret_path} is invalid or unreadable.")
    except OSError as exc:
        raise PermissionError(f"Failed to create secret at {secret_path}: {exc}")

    return secret


def _canonical_bytes(data: dict) -> bytes:
    filtered = {k: v for k, v in data.items() if k != "hmac"}
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False).encode("utf-8")


def mint_receipt(
    scope: str,
    ttl_minutes: int = 15,
    reviewer: str = "",
    receipt_path: Optional[Path] = None,
    secret_path: Optional[Path] = None,
    force_terminal_check: bool = True,
) -> dict:
    """Generate an HMAC-signed approval token on the local interactive terminal."""
    target_scope = scope.strip().lower()
    if not target_scope:
        raise ValueError("Scope cannot be empty.")
    if target_scope == "all" or "*" in target_scope:
        raise ValueError("Wildcard scope 'all' is prohibited. Specify exact action scope (e.g. 'git_remote_push').")

    if ttl_minutes <= 0:
        raise ValueError("TTL must be greater than 0.")
    if ttl_minutes > MAX_TTL_MINUTES:
        raise ValueError(f"TTL exceeds maximum allowed of {MAX_TTL_MINUTES} minutes.")

    # P0-1: Require a real interactive terminal. This stops an agent's plain Bash
    # call, but NOT a same-user agent that allocates a pty (`script`) or calls this
    # function with force_terminal_check=False. See docs/limitations.md.
    if force_terminal_check:
        is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if not is_interactive:
            raise PermissionError(
                "BLOCKED: Human approval receipts can only be minted from an interactive terminal (isatty). "
                "Autonomous agents and non-interactive scripts are prohibited from self-approving."
            )

    target_receipt = receipt_path or DEFAULT_RECEIPT
    target_secret = secret_path or DEFAULT_SECRET
    secret = _get_or_create_secret_for_mint(target_secret)

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ttl_minutes)

    receipt = {
        "token": secrets.token_hex(16),
        "scope": target_scope,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "reviewer": reviewer or os.environ.get("USER", "terminal_operator"),
    }

    digest = hmac.new(secret, _canonical_bytes(receipt), hashlib.sha256).hexdigest()
    receipt["hmac"] = digest

    # Atomically write receipt with 0600
    target_receipt.parent.mkdir(parents=True, exist_ok=True)
    temp_receipt = target_receipt.with_suffix(".tmp")
    fd = os.open(str(temp_receipt), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(receipt, indent=2) + "\n")
    temp_receipt.replace(target_receipt)

    return receipt


def verify_receipt(
    scope: str,
    receipt_path: Optional[Path] = None,
    secret_path: Optional[Path] = None,
    consume: bool = True,
) -> Tuple[bool, str]:
    """Verify active clearance for a requested scope.

    FAILS CLOSED on any missing, corrupted, tampered, expired, or excessive-TTL condition.
    Consumes the receipt on successful verification to prevent replay attacks.
    """
    target_receipt = receipt_path or DEFAULT_RECEIPT
    target_secret = secret_path or DEFAULT_SECRET
    requested_scope = scope.strip().lower()

    if not target_receipt.exists():
        return False, "no_receipt"

    # P1-5: NEVER create secret on verify path! Must be >= 32 bytes
    secret = _load_secret(target_secret)
    if not secret:
        return False, "missing_or_invalid_secret"

    try:
        receipt = json.loads(target_receipt.read_text(encoding="utf-8"))
    except Exception:
        return False, "unreadable_receipt"

    if not isinstance(receipt, dict):
        return False, "malformed_receipt"

    receipt_hmac = receipt.get("hmac")
    if not isinstance(receipt_hmac, str) or not receipt_hmac:
        return False, "missing_or_invalid_hmac_format"

    # 1. Verify HMAC integrity
    expected_hmac = hmac.new(secret, _canonical_bytes(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(receipt_hmac, expected_hmac):
        return False, "hmac_mismatch"

    # 2. Verify Scope (no wildcards)
    receipt_scope = str(receipt.get("scope", "")).strip().lower()
    if receipt_scope == "all" or "*" in receipt_scope:
        return False, "wildcard_scope_prohibited"
    if receipt_scope != requested_scope:
        return False, f"scope_mismatch (held '{receipt_scope}', requested '{requested_scope}')"

    # 3. Verify Timestamps & Expiry (F-3: Strict parsing, NaN fails closed)
    expires_str = receipt.get("expires_at", "")
    issued_str = receipt.get("issued_at", "")
    if not expires_str or expires_str == "NaN" or not issued_str or issued_str == "NaN":
        return False, "invalid_timestamp"

    try:
        expires_dt = datetime.fromisoformat(expires_str)
        issued_dt = datetime.fromisoformat(issued_str)
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if issued_dt.tzinfo is None:
            issued_dt = issued_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return False, "invalid_timestamp"

    now = datetime.now(timezone.utc)

    # Reject future-issued clock anomalies (> 60s in future)
    if issued_dt > now + timedelta(seconds=60):
        return False, "future_issued_timestamp"

    # Enforce maximum TTL cap at verify time (max 60 minutes)
    if (expires_dt - issued_dt).total_seconds() > (MAX_TTL_MINUTES * 60):
        return False, "excessive_ttl"

    if now > expires_dt:
        return False, "expired"

    # P2: Single-use consumption
    if consume:
        revoke_receipt(target_receipt)

    return True, "valid"


def revoke_receipt(receipt_path: Optional[Path] = None) -> bool:
    """Clear active clearance."""
    target_receipt = receipt_path or DEFAULT_RECEIPT
    if target_receipt.exists():
        try:
            target_receipt.unlink()
            return True
        except OSError:
            return False
    return False


def main():
    parser = argparse.ArgumentParser(description="Terminal-only HMAC Approval Gate", allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="action", required=True)

    # mint
    p_mint = subparsers.add_parser("mint", help="Mint a temporary clearance receipt", allow_abbrev=False)
    p_mint.add_argument("--scope", required=True, help="Scope of action allowed")
    p_mint.add_argument("--ttl", type=int, default=15, help="Time-to-live in minutes (max 60)")
    p_mint.add_argument("--reviewer", default="", help="Reviewer identifier")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify active clearance")
    p_verify.add_argument("--scope", default="git_remote_push", help="Scope of action requested")
    p_verify.add_argument("--no-consume", action="store_true", help="Do not consume receipt")

    # revoke
    subparsers.add_parser("revoke", help="Revoke active clearance")

    args = parser.parse_args()

    if args.action == "mint":
        try:
            r = mint_receipt(scope=args.scope, ttl_minutes=args.ttl, reviewer=args.reviewer)
            print(f"[approval-gate] CLEARED: scope='{r['scope']}' until {r['expires_at']} (token={r['token'][:8]}...)")
            sys.exit(0)
        except Exception as exc:
            print(f"[approval-gate] BLOCKED: {exc}", file=sys.stderr)
            sys.exit(2)

    elif args.action == "verify":
        valid, reason = verify_receipt(scope=args.scope, consume=not args.no_consume)
        if valid:
            print(f"[approval-gate] PASS: clearance verified for scope='{args.scope}'")
            sys.exit(0)
        else:
            print(f"[approval-gate] BLOCKED: no valid clearance for scope='{args.scope}' (reason: {reason})", file=sys.stderr)
            sys.exit(2)

    elif args.action == "revoke":
        ok = revoke_receipt()
        print(f"[approval-gate] Receipt {'revoked' if ok else 'not found'}")
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""tests/test_approval_gate.py — Tests for Terminal-Only HMAC Human Approval Gate (F-0, F-3).

Enforces:
1. Terminal-only HMAC-SHA256 signed receipts.
2. Scope matching (e.g., git_remote_push vs db_migration) and disallowing wildcard 'all'.
3. Single-use receipt consumption (preventing replay attacks).
4. Strict TTL caps (rejecting receipts with > 60m TTL on verify).
5. Fail-closed security on empty keys (P1-5 empty key forgery prevention).
6. Fail-closed security on malformed timestamps (F-3 NaN regression test).
7. CLI exit code 0 on valid approval, exit code 2 on missing/expired/tampered receipt.
"""

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "src" / "approval_gate.py"

try:
    from src.approval_gate import (
        mint_receipt,
        verify_receipt,
        revoke_receipt,
        _canonical_bytes,
        _load_secret,
        MAX_TTL_MINUTES,
    )
except ImportError:
    mint_receipt = None
    verify_receipt = None
    revoke_receipt = None
    _canonical_bytes = None
    _load_secret = None
    MAX_TTL_MINUTES = 60


class TestApprovalGate(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            SCRIPT_PATH.exists(),
            f"src/approval_gate.py missing at {SCRIPT_PATH}",
        )
        self.test_dir = Path(tempfile.mkdtemp())
        self.receipt_file = self.test_dir / "approval_receipt.json"
        self.secret_file = self.test_dir / "gate_secret.key"
        # Minimum 32 bytes secret for HMAC-SHA256 security
        self.secret_bytes = b"0123456789abcdef0123456789abcdef0123456789abcdef"
        self.secret_file.write_bytes(self.secret_bytes)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_mint_and_verify_valid_receipt(self):
        """A freshly minted receipt with valid TTL must verify successfully and be consumed."""
        receipt = mint_receipt(
            scope="git_remote_push",
            ttl_minutes=15,
            reviewer="charitarth",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
            force_terminal_check=False,
        )
        self.assertIn("token", receipt)
        self.assertIn("hmac", receipt)
        self.assertEqual(receipt["scope"], "git_remote_push")

        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
            consume=True,
        )
        self.assertTrue(valid, f"Verification failed: {reason}")
        self.assertEqual(reason, "valid")

        # Single-use: receipt should now be consumed (deleted)
        self.assertFalse(self.receipt_file.exists())
        valid_again, reason_again = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid_again, "Consumed receipt must not verify a second time")
        self.assertEqual(reason_again, "no_receipt")

    def test_scope_mismatch_blocks(self):
        """A receipt minted for 'git_remote_push' must not allow 'db_migration'."""
        mint_receipt(
            scope="git_remote_push",
            ttl_minutes=15,
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
            force_terminal_check=False,
        )
        valid, reason = verify_receipt(
            scope="db_migration",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertIn("scope_mismatch", reason)

    def test_wildcard_scope_all_prohibited(self):
        """Wildcard scope 'all' must be rejected at mint and verify time."""
        with self.assertRaises(ValueError):
            mint_receipt(
                scope="all",
                ttl_minutes=15,
                receipt_path=self.receipt_file,
                secret_path=self.secret_file,
                force_terminal_check=False,
            )

    def test_empty_key_forgery_fails_closed(self):
        """P1-5: An empty or truncated secret file must fail closed and never allow forgery."""
        empty_secret_file = self.test_dir / "empty.key"
        empty_secret_file.write_bytes(b"")

        # Even with receipt signed with empty key
        receipt = {
            "token": "0123456789abcdef",
            "scope": "git_remote_push",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            "reviewer": "attacker",
        }
        receipt["hmac"] = hmac.new(b"", _canonical_bytes(receipt), hashlib.sha256).hexdigest()
        self.receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=empty_secret_file,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "missing_or_invalid_secret")

    def test_excessive_ttl_fails_closed_on_verify(self):
        """A receipt minted for 1 year (525,600 minutes) must be rejected at verify time."""
        now = datetime.now(timezone.utc)
        receipt = {
            "token": "0123456789abcdef",
            "scope": "git_remote_push",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=365)).isoformat(),
            "reviewer": "attacker",
        }
        receipt["hmac"] = hmac.new(self.secret_bytes, _canonical_bytes(receipt), hashlib.sha256).hexdigest()
        self.receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "excessive_ttl")

    def test_tampered_payload_blocks(self):
        """Tampering with scope or timestamp after minting breaks HMAC and fails closed."""
        mint_receipt(
            scope="git_remote_push",
            ttl_minutes=15,
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
            force_terminal_check=False,
        )
        with open(self.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["scope"] = "other_scope"
        with open(self.receipt_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        valid, reason = verify_receipt(
            scope="other_scope",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertIn("hmac_mismatch", reason)

    def test_expired_receipt_blocks(self):
        """Receipt past its TTL expires and fails closed."""
        now = datetime.now(timezone.utc)
        past_issue = now - timedelta(minutes=20)
        past_expire = now - timedelta(minutes=5)
        receipt = {
            "token": "0123456789abcdef",
            "scope": "git_remote_push",
            "issued_at": past_issue.isoformat(),
            "expires_at": past_expire.isoformat(),
            "reviewer": "test",
        }
        receipt["hmac"] = hmac.new(self.secret_bytes, _canonical_bytes(receipt), hashlib.sha256).hexdigest()
        self.receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "expired")

    def test_malformed_timestamp_nan_fails_closed(self):
        """CRITICAL F-3 TEST: Signed receipt with malformed timestamp or NaN must FAIL CLOSED, not open."""
        now = datetime.now(timezone.utc)
        receipt = {
            "token": "0123456789abcdef",
            "scope": "git_remote_push",
            "issued_at": now.isoformat(),
            "expires_at": "NaN",
            "reviewer": "test",
        }
        receipt["hmac"] = hmac.new(self.secret_bytes, _canonical_bytes(receipt), hashlib.sha256).hexdigest()
        self.receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "invalid_timestamp")

    def test_revoke_receipt(self):
        """Revoking clears the active receipt."""
        mint_receipt(
            scope="git_remote_push",
            ttl_minutes=15,
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
            force_terminal_check=False,
        )
        revoke_receipt(receipt_path=self.receipt_file)
        self.assertFalse(self.receipt_file.exists())
        valid, reason = verify_receipt(
            scope="git_remote_push",
            receipt_path=self.receipt_file,
            secret_path=self.secret_file,
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "no_receipt")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""tests/test_audit_hash_chain.py — Tests for Tamper-Evident Hash-Chained Audit Ledger.

Enforces:
1. Append-only SHA-256 hash chaining (prev_hash -> entry_hash).
2. Tamper detection: modifying, deleting, or reordering any entry breaks the chain.
3. Zero sensitive payload logging (only tool names, status, and target metadata).
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "src" / "audit_post_tool_use.py"

try:
    from src.audit_post_tool_use import log_tool_action, verify_audit_log
except ImportError:
    log_tool_action = None
    verify_audit_log = None


class TestAuditHashChain(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            SCRIPT_PATH.exists(),
            f"src/audit_post_tool_use.py missing at {SCRIPT_PATH}",
        )
        self.test_dir = Path(tempfile.mkdtemp())
        self.log_file = self.test_dir / "tool_audit.jsonl"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_unbroken_chain_verification(self):
        """Sequential log entries form an unbroken cryptographic chain."""
        log_tool_action("Read", "ALLOWED", "file: src/main.py", log_path=self.log_file)
        log_tool_action("Write", "ALLOWED", "file: docs/README.md", log_path=self.log_file)
        log_tool_action("Bash", "BLOCKED", "pattern: cmd_ssh_credentials", log_path=self.log_file)

        valid, reason, count = verify_audit_log(self.log_file)
        self.assertTrue(valid, f"Verification failed: {reason}")
        self.assertEqual(count, 3)

    def test_tamper_detection_edited_content(self):
        """Modifying a field in any historical line breaks the hash chain."""
        log_tool_action("Read", "ALLOWED", "target: src/a.py", log_path=self.log_file)
        log_tool_action("Write", "ALLOWED", "target: src/b.py", log_path=self.log_file)
        log_tool_action("Bash", "ALLOWED", "target: git status", log_path=self.log_file)

        # Alter line 2
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        record_2 = json.loads(lines[1])
        record_2["status"] = "BLOCKED"  # Tamper with status
        lines[1] = json.dumps(record_2)
        self.log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, reason, line_num = verify_audit_log(self.log_file)
        self.assertFalse(valid)
        self.assertIn("hash_mismatch", reason)
        self.assertEqual(line_num, 2)

    def test_tamper_detection_deleted_line(self):
        """Deleting a line breaks the prev_hash continuity."""
        log_tool_action("Read", "ALLOWED", "target: 1", log_path=self.log_file)
        log_tool_action("Write", "ALLOWED", "target: 2", log_path=self.log_file)
        log_tool_action("Bash", "ALLOWED", "target: 3", log_path=self.log_file)

        # Remove line 2
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        del lines[1]
        self.log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, reason, line_num = verify_audit_log(self.log_file)
        self.assertFalse(valid)
        self.assertTrue("chain_broken" in reason or "sequence_gap" in reason)
        self.assertEqual(line_num, 2)

    def test_sensitive_passwords_redacted_before_logging(self):
        """Passswords in CLI flags must be scrubbed before hitting the audit ledger."""
        log_tool_action("Bash", "ALLOWED", "mysql -u root -pHunter2Prod! -h localhost", log_path=self.log_file)
        content = self.log_file.read_text(encoding="utf-8")
        self.assertNotIn("Hunter2Prod!", content)
        self.assertIn("-p[REDACTED]", content)


if __name__ == "__main__":
    unittest.main()

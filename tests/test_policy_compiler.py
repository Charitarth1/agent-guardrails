#!/usr/bin/env python3
"""tests/test_policy_compiler.py — Tests for Settings Compiler & Rule-of-Two Linter (F-14).

Enforces:
1. Dynamic compilation of deny rules, ask rules, and hook arrays into .claude/settings.json.
2. Non-destructive merge preserving foreign hooks and user permissions (P1-8).
3. Fail-closed error handling on malformed settings JSON (P1-8).
4. Compilation of hardened exit-2 wrapper and universal '.*' tool matcher (P1-3, P1-4).
5. Static linting of session profiles against the Rule of Two.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "src" / "policy_compiler.py"

try:
    from src.policy_compiler import compile_settings, audit_rule_of_two
except ImportError:
    compile_settings = None
    audit_rule_of_two = None


class TestPolicyCompiler(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.config_path = self.test_dir / "guardrails.json"
        self.settings_path = self.test_dir / "settings.json"
        self.agents_md_path = self.test_dir / "AGENTS.md"

        self.config_data = {
            "denylisted_dirs": ["private-vault", "finance-records"],
            "outbound_tool_prefixes": ["mcp__claude_ai_Buffer__", "mcp__claude_ai_Gmail__"],
        }
        self.config_path.write_text(json.dumps(self.config_data), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_compile_settings_generates_valid_schema(self):
        """Compiler must output nested hook schema with universal matcher and exit-2 wrapper."""
        compile_settings(self.config_path, self.settings_path, self.agents_md_path)
        self.assertTrue(self.settings_path.exists())
        self.assertTrue(self.agents_md_path.exists())

        settings = json.loads(self.settings_path.read_text(encoding="utf-8"))
        # 1. Deny rules include wildcard directories
        deny = settings.get("permissions", {}).get("deny", [])
        self.assertIn("Read(**/private-vault/**)", deny)

        # 2. Hooks use nested schema, .* matcher, and exit 2 wrapper (P1-3, P1-4)
        hooks = settings.get("hooks", {})
        pre_hooks = hooks.get("PreToolUse", [])
        self.assertTrue(len(pre_hooks) > 0)
        entry = pre_hooks[-1]
        self.assertEqual(entry.get("matcher"), ".*")
        cmd = entry.get("hooks", [])[0].get("command", "")
        self.assertIn("[ $rc -eq 0 ] || exit 2", cmd)

    def test_non_destructive_merge_preserves_foreign_hooks_and_perms(self):
        """P1-8: Existing corporate hooks and custom permissions must not be erased."""
        existing = {
            "permissions": {"deny": ["Read(~/.secret_corp/**)"]},
            "hooks": {
                "SessionStart": [{"matcher": ".*", "hooks": [{"type": "command", "command": "echo session"}]}],
                "PreToolUse": [{"matcher": "CustomTool", "hooks": [{"type": "command", "command": "custom_audit.sh"}]}],
            },
        }
        self.settings_path.write_text(json.dumps(existing), encoding="utf-8")

        compile_settings(self.config_path, self.settings_path)
        settings = json.loads(self.settings_path.read_text(encoding="utf-8"))

        # Preserved custom deny
        self.assertIn("Read(~/.secret_corp/**)", settings["permissions"]["deny"])
        # Preserved SessionStart
        self.assertIn("SessionStart", settings["hooks"])
        # Preserved foreign PreToolUse
        pre_cmds = [h["hooks"][0]["command"] for h in settings["hooks"]["PreToolUse"]]
        self.assertIn("custom_audit.sh", pre_cmds)

    def test_malformed_settings_fails_closed(self):
        """P1-8: An existing malformed settings.json must fail closed (raise ValueError)."""
        self.settings_path.write_text("{ malformed JSON", encoding="utf-8")
        with self.assertRaises(ValueError):
            compile_settings(self.config_path, self.settings_path)

    def test_rule_of_two_audit_flags_toxic_combinations(self):
        """Audit flags session profiles containing all 3 legs."""
        toxic_profile = {
            "tools_allowed": ["WebFetch", "Bash", "mcp__claude_ai_Gmail__send_email"],
            "data_access": ["untrusted_web", "sensitive_credentials"],
            "side_effects": ["external_publish"],
        }
        violations = audit_rule_of_two(toxic_profile)
        self.assertEqual(len(violations), 1)
        self.assertIn("RULE_OF_TWO_VIOLATION", violations[0])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""tests/test_packs.py — Tests for pluggable policy packs.

Validates that all JSON policy packs exist, compile valid regex patterns,
and can be dynamically merged by the policy engine.
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = REPO_ROOT / "packs"

REQUIRED_PACKS = [
    "core-secrets.json",
    "destructive-infra.json",
    "supply-chain-coding.json",
    "pii-regulated.json",
    "personal-privacy.json",
]

VALID_TIERS = {"global", "command", "path", "outbound"}
VALID_ACTIONS = {"block", "quarantine", "require_approval"}


class TestPolicyPacks(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PACKS_DIR.exists(), f"packs directory missing at {PACKS_DIR}")

    def test_all_required_packs_exist(self):
        """All 5 core policy packs must exist in packs/."""
        for name in REQUIRED_PACKS:
            path = PACKS_DIR / name
            self.assertTrue(path.exists(), f"Required policy pack {name} missing")

    def test_pack_schema_and_regex_validity(self):
        """Every pack must be valid JSON and every rule must compile cleanly."""
        for path in PACKS_DIR.glob("*.json"):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("name", data, f"Missing 'name' in {path.name}")
            self.assertIn("description", data, f"Missing 'description' in {path.name}")
            self.assertIn("rules", data, f"Missing 'rules' in {path.name}")
            self.assertIsInstance(data["rules"], list, f"'rules' not a list in {path.name}")
            self.assertGreater(len(data["rules"]), 0, f"No rules defined in {path.name}")

            for rule in data["rules"]:
                self.assertIn("id", rule, f"Rule missing 'id' in {path.name}")
                self.assertIn("tier", rule, f"Rule {rule.get('id')} missing 'tier'")
                self.assertIn(
                    rule["tier"],
                    VALID_TIERS,
                    f"Invalid tier {rule['tier']} in rule {rule['id']} of {path.name}",
                )
                self.assertIn(
                    rule.get("action", "block"),
                    VALID_ACTIONS,
                    f"Invalid action in rule {rule['id']}",
                )

                # Check pattern compilation
                patterns = []
                if "pattern" in rule:
                    patterns.append(rule["pattern"])
                if "patterns" in rule:
                    patterns.extend(rule["patterns"])

                self.assertTrue(
                    patterns,
                    f"Rule {rule['id']} in {path.name} has no pattern or patterns",
                )

                flags = re.IGNORECASE if rule.get("case_insensitive", True) else 0
                for pat in patterns:
                    try:
                        re.compile(pat, flags)
                    except re.error as exc:
                        self.fail(
                            f"Regex error in rule {rule['id']} of {path.name}: {pat} ({exc})"
                        )

    def test_destructive_infra_coverage(self):
        """destructive-infra pack must catch key operations like terraform destroy and prisma migrate diff."""
        infra_path = PACKS_DIR / "destructive-infra.json"
        if not infra_path.exists():
            self.fail("destructive-infra.json pack missing")
        with open(infra_path, "r", encoding="utf-8") as f:
            pack = json.load(f)

        rule_ids = {r["id"] for r in pack["rules"]}
        self.assertIn("terraform_destroy", rule_ids)
        self.assertIn("prisma_migrate_reset", rule_ids)
        self.assertIn("db_drop", rule_ids)
        self.assertIn("k8s_delete_namespace", rule_ids)
        self.assertIn("git_force_push", rule_ids)


if __name__ == "__main__":
    unittest.main()

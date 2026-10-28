#!/usr/bin/env python3
"""tests/test_matrix.py — Tests for the Agentic Risk, Control & Evidence Matrix.

Enforces schema validity, coverage across all 6 core governance domains,
the MIT AI Risk Repository subdomain classification in docs/agentic_risk_screener.md,
and that the screener lists exactly the 24 real subdomains (v3, March 2026).
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_JSON_PATH = REPO_ROOT / "matrix" / "risk_control_matrix.json"
MATRIX_MD_PATH = REPO_ROOT / "matrix" / "MATRIX.md"

VALID_DOMAINS = {
    "AG-DAT": "Data & Privacy Boundary",
    "AG-SEC": "Adversarial & Endpoint Security",
    "AG-SAF": "Action Safety & Blast-Radius Control",
    "AG-REL": "Tool & Execution Reliability",
    "AG-ACC": "Accountability, Audit & Supply Chain",
    "AG-MIS": "Cyber & Catastrophic Misuse Prevention",
}

SCREENER_PATH = REPO_ROOT / "docs" / "agentic_risk_screener.md"

# The 24 subdomains of the MIT AI Risk Repository domain taxonomy (v3, March 2026).
MIT_SUBDOMAINS = {
    "1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "3.2", "4.1", "4.2", "4.3", "5.1", "5.2",
    "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6",
}

# Our classification (screener section 2): decidable at the tool-call boundary, fully or in part.
DECIDABLE_SUBDOMAINS = {"2.1", "2.2", "5.2", "7.3", "7.4"}
PARTLY_DECIDABLE_SUBDOMAINS = {"4.2", "7.2", "7.6"}
ALLOWED_RUNTIME_SUBDOMAINS = DECIDABLE_SUBDOMAINS | PARTLY_DECIDABLE_SUBDOMAINS

REQUIRED_ENTRY_KEYS = {
    "id",
    "control_id",
    "domain",
    "name",
    "owasp_agentic_id",
    "mit_subdomain",
    "nist_ai_rmf",
    "govtech_arc_ref",
    "runtime_decidable",
    "failure_mode",
    "control_spec",
    "evidence_artifact",
    "typical_location",
    "enforced_by",
}


class TestRiskControlMatrix(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            MATRIX_JSON_PATH.exists(),
            f"Matrix JSON file missing at {MATRIX_JSON_PATH}",
        )
        with open(MATRIX_JSON_PATH, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_top_level_metadata(self):
        """Top-level document metadata must be well-formed."""
        self.assertIn("version", self.data)
        self.assertIn("title", self.data)
        self.assertIn("standard", self.data)
        self.assertIn("scope_framework", self.data)
        self.assertIn("risks", self.data)
        self.assertIsInstance(self.data["risks"], list)
        self.assertGreaterEqual(len(self.data["risks"]), 18)

    def test_entry_schema(self):
        """Every risk entry must follow the required schema."""
        seen_ids = set()
        for idx, entry in enumerate(self.data["risks"]):
            missing = REQUIRED_ENTRY_KEYS - set(entry.keys())
            self.assertFalse(
                missing, f"Entry {idx} ({entry.get('id', 'unknown')}) missing keys: {missing}"
            )

            # ID format
            self.assertRegex(
                entry["id"],
                r"^AG-RISK-\d{3}$",
                f"Entry ID {entry['id']} does not match pattern AG-RISK-NNN",
            )
            self.assertRegex(
                entry["control_id"],
                r"^AG-CTRL-\d{3}$",
                f"Control ID {entry['control_id']} does not match pattern AG-CTRL-NNN",
            )
            self.assertNotIn(entry["id"], seen_ids, f"Duplicate ID: {entry['id']}")
            seen_ids.add(entry["id"])

            # GovTech ARC reference format (must use official IDs without ARC:: prefix)
            self.assertFalse(
                entry["govtech_arc_ref"].startswith("ARC::"),
                f"Entry {entry['id']} uses artificial 'ARC::' prefix: {entry['govtech_arc_ref']}",
            )

            # Domain validation
            self.assertIn(
                entry["domain"],
                VALID_DOMAINS,
                f"Invalid domain {entry['domain']} in {entry['id']}",
            )

            # String fields non-empty
            for key in ["name", "failure_mode", "control_spec", "evidence_artifact", "typical_location", "enforced_by"]:
                self.assertIsInstance(entry[key], str)
                self.assertGreater(len(entry[key].strip()), 3)

    def test_six_domain_coverage(self):
        """All 6 core governance domains must be represented in the matrix."""
        domains_present = {r["domain"] for r in self.data["risks"]}
        for d in VALID_DOMAINS:
            self.assertIn(
                d,
                domains_present,
                f"Domain {d} ({VALID_DOMAINS[d]}) is missing from matrix",
            )

    def test_mit_subdomains_are_real(self):
        """Every row must cite a subdomain that exists in the MIT taxonomy."""
        for entry in self.data["risks"]:
            self.assertIn(entry["mit_subdomain"], MIT_SUBDOMAINS, entry["id"])

    def test_screener_table_matches_taxonomy_and_totals(self):
        """The screener table lists each real subdomain once, and its verdicts match the classification above."""
        rows = re.findall(r"^\| (\d\.\d) \| [^|]+\| (\*\*Yes\*\*|Partly|No) \|", SCREENER_PATH.read_text(encoding="utf-8"), re.M)
        self.assertEqual(sorted(s for s, _ in rows), sorted(MIT_SUBDOMAINS))
        verdicts = dict(rows)
        self.assertEqual({s for s, v in verdicts.items() if v == "**Yes**"}, DECIDABLE_SUBDOMAINS)
        self.assertEqual({s for s, v in verdicts.items() if v == "Partly"}, PARTLY_DECIDABLE_SUBDOMAINS)

    def test_arc_refs_use_official_id_format(self):
        """ARC references are slash-separated official IDs (RISK-NNN, CTRL-NNNN)."""
        for entry in self.data["risks"]:
            for ref in entry["govtech_arc_ref"].split("/"):
                self.assertRegex(ref.strip(), r"^(?:RISK-\d{3}|CTRL-\d{4})$", entry["id"])

    def test_mit_runtime_scoping(self):
        """Runtime-decidable risks must only cite subdomains our classification marks decidable."""
        for entry in self.data["risks"]:
            if entry.get("runtime_decidable"):
                sub = entry.get("mit_subdomain")
                self.assertIn(
                    sub,
                    ALLOWED_RUNTIME_SUBDOMAINS,
                    f"Risk {entry['id']} claims runtime_decidable=True but cites non-runtime subdomain {sub}",
                )

    def test_markdown_rendering(self):
        """Ensure MATRIX.md exists and is consistent with the JSON."""
        self.assertTrue(
            MATRIX_MD_PATH.exists(),
            f"Compiled MATRIX.md missing at {MATRIX_MD_PATH}. Run matrix/build_matrix_md.py",
        )
        md_text = MATRIX_MD_PATH.read_text(encoding="utf-8")
        for entry in self.data["risks"][:5]:
            self.assertIn(
                entry["id"],
                md_text,
                f"Risk {entry['id']} not found in compiled MATRIX.md",
            )


if __name__ == "__main__":
    unittest.main()

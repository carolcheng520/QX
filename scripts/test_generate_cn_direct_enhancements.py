#!/usr/bin/env python3
"""Adversarial checks for generate_cn_direct_enhancements.py."""

from __future__ import annotations

import argparse
import sys
import tempfile
import unittest
from collections import Counter
from datetime import date
from pathlib import Path


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_cn_direct_enhancements as generator  # noqa: E402


class GenerateCNDirectEnhancementsTest(unittest.TestCase):
    def test_remote_paths_are_rejected_before_loading(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            generator.local_path_arg("https://example.com/Geosite_CN.arrs")

    def test_require_sources_reports_all_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            first = Path(tmpdir) / "missing-one.arrs"
            second = Path(tmpdir) / "missing-two.arrs"

            with self.assertRaises(SystemExit) as raised:
                generator.require_sources([("one", first), ("two", second)])

        message = str(raised.exception)
        self.assertIn("Missing input source file(s):", message)
        self.assertIn("missing-one.arrs", message)
        self.assertIn("missing-two.arrs", message)

    def test_parse_arrs_rejects_malformed_lines(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            generator.parse_arrs("2, valid.example\ninvalid-line\n", "fixture.arrs")

        self.assertIn("fixture.arrs:2: invalid rule line", str(raised.exception))

    def test_geosite_delta_defends_against_all_exclusion_layers(self) -> None:
        geosite_rules = [
            (2, "baseline.example.com"),
            (2, "adblock.example.com"),
            (2, "ads-img-qc.xhscdn.com"),
            (2, "xhscdn.com"),
            (3, "keyword"),
            (2, "safe.example.com"),
        ]
        output, skipped = generator.generate_geosite_delta(
            geosite_rules,
            builtin_cn_rules=[(2, "baseline.example.com")],
            direct_rules=[],
            adblock_rules=[(2, "adblock.example.com")],
            mitm_reject_rules=[(2, "ads-img-qc.xhscdn.com")],
        )

        self.assertEqual(output, [(2, "safe.example.com")])
        self.assertEqual(skipped["baseline-covered"], 1)
        self.assertEqual(skipped["adblock-covered"], 1)
        self.assertEqual(skipped["mitm-reject-covered"], 2)
        self.assertEqual(skipped["type3"], 1)

    def test_validate_geosite_delta_rejects_parent_suffix_conflict(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            generator.validate_geosite_delta(
                rules=[(2, "xhscdn.com")],
                builtin_cn_rules=[],
                direct_rules=[],
                adblock_rules=[],
                mitm_reject_rules=[(2, "ads-img-qc.xhscdn.com")],
            )

        self.assertIn("conflicts with MITM reject domains", str(raised.exception))

    def test_mitm_reject_loader_keeps_only_domain_suffix_rules(self) -> None:
        source = generator.SourceText(
            text="2, reject.example.com\n3, keyword\n0, 192.0.2.1/32\n",
            sha256="unused",
            location=Path("fixture.arrs"),
            label="fixture.arrs",
        )

        rules, skipped = generator.load_mitm_reject_rules([("fixture.arrs", source)])

        self.assertEqual(rules, [(2, "reject.example.com")])
        self.assertEqual(skipped, Counter({"mitm-reject-type3": 1, "mitm-reject-type0": 1}))

    def test_output_last_updated_preserves_date_only_when_rules_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rules.arrs"
            path.write_text(
                "# LAST-UPDATED: 2026-06-28\n"
                "name = Fixture\n"
                "2, example.com\n",
                encoding="utf-8",
            )

            self.assertEqual(
                generator.output_last_updated(path, [(2, "example.com")]),
                "2026-06-28",
            )
            self.assertEqual(
                generator.output_last_updated(path, [(2, "changed.example.com")]),
                date.today().isoformat(),
            )

    def test_write_output_does_not_rewrite_identical_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.arrs"
            path.write_text("same\n", encoding="utf-8")

            self.assertFalse(generator.write_output(path, "same\n"))
            self.assertTrue(generator.write_output(path, "changed\n"))
            self.assertEqual(path.read_text(encoding="utf-8"), "changed\n")


if __name__ == "__main__":
    unittest.main()

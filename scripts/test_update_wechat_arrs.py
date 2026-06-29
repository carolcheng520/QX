#!/usr/bin/env python3
"""Checks for update_wechat_arrs.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import update_wechat_arrs as updater  # noqa: E402


class UpdateWeChatArrsTest(unittest.TestCase):
    def test_parse_rules_skips_surge_only_types(self) -> None:
        rules, skipped = updater.parse_rules(
            "\n".join(
                [
                    "DOMAIN,example.qq.com",
                    "DOMAIN-SUFFIX,weixin.qq.com",
                    "DOMAIN-KEYWORD,101.226.129.",
                    "IP-CIDR,111.30.160.0/20,no-resolve",
                    "IP-CIDR6,240e:ff:f100::/44,no-resolve",
                    "IP-ASN,132203,no-resolve",
                    "USER-AGENT,WeChat*",
                ]
            )
        )

        self.assertEqual(
            rules,
            [
                ("2", "example.qq.com"),
                ("2", "weixin.qq.com"),
                ("0", "111.30.160.0/20"),
                ("1", "240e:ff:f100::/44"),
            ],
        )
        self.assertEqual(skipped["DOMAIN-KEYWORD"], 1)
        self.assertEqual(skipped["IP-ASN"], 1)
        self.assertEqual(skipped["USER-AGENT"], 1)

    def test_parse_rules_rejects_real_domain_keywords(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            updater.parse_rules("DOMAIN-KEYWORD,wechat\n")

        self.assertIn("Refusing to drop non-IP-prefix DOMAIN-KEYWORD", str(raised.exception))

    def test_build_rules_keeps_maintained_supplemental_rules(self) -> None:
        source_rules = [
            ("2", "apd-pcdnwxlogin.teg.tencent-cloud.net"),
            ("2", "dldir1.qq.com"),
            ("1", "240e:95c:2003:20::/60"),
            ("1", "240e:f7:a070:100::/60"),
        ]

        self.assertEqual(
            updater.build_rules(source_rules),
            [
                ("2", "apd-pcdnwxlogin.teg.tencent-cloud.net"),
                ("2", "btrace.qq.com"),
                ("2", "dldir1.qq.com"),
                ("1", "240e:95c:2003:20::/60"),
                ("1", "240e:95c:3003:10::/60"),
                ("1", "240e:f7:a070:100::/60"),
                ("1", "240e:f7:a070:400::/60"),
            ],
        )

    def test_validate_supplemental_rules_uses_cidr_semantics(self) -> None:
        updater.validate_supplemental_rules(
            "\n".join(
                [
                    "1, 240E:95C:3003:14::/60",
                    "1, 240E:F7:A070:403::/60",
                    "2, btrace.qq.com",
                ]
            )
        )

    def test_validate_supplemental_rules_rejects_missing_source_rules(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            updater.validate_supplemental_rules("2, btrace.qq.com\n")

        self.assertIn("Supplemental WeChat rule(s) are missing", str(raised.exception))
        self.assertIn("240e:95c:3003:10::/60", str(raised.exception))

    def test_complete_generation_reproduces_current_output(self) -> None:
        current_text = updater.OUTPUT_PATH.read_text(encoding="utf-8")
        supplemental_rules = {rule for rule, _ in updater.SUPPLEMENTAL_RULES}
        surge_lines: list[str] = []

        for line in current_text.splitlines():
            if not line or not line[0].isdigit():
                continue
            rule_type, value = [part.strip() for part in line.split(",", 1)]
            if (rule_type, value) in supplemental_rules:
                continue
            if rule_type == "0":
                surge_lines.append(f"IP-CIDR,{value},no-resolve")
            elif rule_type == "1":
                surge_lines.append(f"IP-CIDR6,{value},no-resolve")
            elif rule_type == "2":
                surge_lines.append(f"DOMAIN-SUFFIX,{value}")

        source_rules, _ = updater.parse_rules("\n".join(surge_lines))
        rules = updater.build_rules(source_rules)
        rendered = updater.render_rules(rules, updater.output_last_updated(updater.OUTPUT_PATH, rules))
        updater.validate_output(rendered, len(rules))

        self.assertEqual(rendered, current_text)

    def test_output_last_updated_preserves_date_only_when_rules_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "wechat.arrs"
            path.write_text(
                "# LAST-UPDATED: 2026-06-20\n"
                "name = WeChat\n"
                "2, example.qq.com\n",
                encoding="utf-8",
            )

            self.assertEqual(
                updater.output_last_updated(path, [("2", "example.qq.com")]),
                "2026-06-20",
            )
            self.assertNotEqual(
                updater.output_last_updated(path, [("2", "changed.qq.com")]),
                "2026-06-20",
            )

    def test_write_output_does_not_rewrite_identical_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "wechat.arrs"
            path.write_text("same\n", encoding="utf-8")

            self.assertFalse(updater.write_output(path, "same\n"))
            self.assertTrue(updater.write_output(path, "changed\n"))
            self.assertEqual(path.read_text(encoding="utf-8"), "changed\n")


if __name__ == "__main__":
    unittest.main()

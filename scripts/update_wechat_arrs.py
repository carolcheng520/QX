#!/usr/bin/env python3
"""Generate the maintained Anywhere WeChat routing rule set."""

from __future__ import annotations

import ipaddress
import re
import sys
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path


SOURCE_URL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/WeChat/WeChat.list"
SUPPLEMENTAL_SOURCE_URL = "https://raw.githubusercontent.com/chikacya/anywhere-rules/main/rules/common/WeChat.arrs"
OUTPUT_PATH = Path(__file__).resolve().parents[1] / "rules" / "wechat.arrs"
RAW_LINK = "https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/wechat.arrs"
Rule = tuple[str, str]

IPV4_PREFIX_RE = re.compile(r"^(?:\d{1,3}\.){2,3}$")
SUPPORTED_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
SKIPPED_TYPES = {"DOMAIN-KEYWORD", "IP-ASN", "USER-AGENT"}
SUPPLEMENTAL_RULES: list[tuple[Rule, Rule]] = [
    (("2", "btrace.qq.com"), ("2", "apd-pcdnwxlogin.teg.tencent-cloud.net")),
    (("1", "240e:95c:3003:10::/60"), ("1", "240e:95c:2003:20::/60")),
    (("1", "240e:f7:a070:400::/60"), ("1", "240e:f7:a070:100::/60")),
]
FORBIDDEN_OUTPUT_TOKENS = ["3,", "DOMAIN-KEYWORD", "IP-ASN", "USER-AGENT", "no-resolve"]


def fetch_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def fetch_source() -> str:
    return fetch_url(SOURCE_URL)


def fetch_supplemental_source() -> str:
    return fetch_url(SUPPLEMENTAL_SOURCE_URL)


def is_ipv4_prefix_keyword(value: str) -> bool:
    if not IPV4_PREFIX_RE.fullmatch(value):
        return False
    octets = [part for part in value.split(".") if part]
    return all(0 <= int(octet) <= 255 for octet in octets)


def convert_rule(rule_type: str, value: str) -> Rule | None:
    normalized = value.strip().lower()
    if not normalized:
        return None

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return ("2", normalized)
    if rule_type == "IP-CIDR":
        return ("0", str(ipaddress.IPv4Network(normalized, strict=False)))
    if rule_type == "IP-CIDR6":
        return ("1", str(ipaddress.IPv6Network(normalized, strict=False)))
    return None


def dedupe_preserving_order(rules: list[Rule]) -> list[Rule]:
    output: list[Rule] = []
    seen: set[Rule] = set()
    for rule in rules:
        if rule in seen:
            continue
        seen.add(rule)
        output.append(rule)
    return output


def parse_rules(text: str) -> tuple[list[Rule], Counter[str]]:
    rules: list[Rule] = []
    skipped: Counter[str] = Counter()
    unsafe_keywords: list[str] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()
        value = parts[1] if len(parts) > 1 else ""

        if rule_type == "DOMAIN-KEYWORD":
            if not is_ipv4_prefix_keyword(value):
                unsafe_keywords.append(f"line {line_number}: {value}")
            skipped[rule_type] += 1
            continue

        if rule_type in SKIPPED_TYPES:
            skipped[rule_type] += 1
            continue

        if rule_type not in SUPPORTED_TYPES:
            skipped[rule_type or "UNKNOWN"] += 1
            continue

        try:
            converted = convert_rule(rule_type, value)
        except ValueError as exc:
            raise SystemExit(f"Invalid {rule_type} at line {line_number}: {value} ({exc})") from exc

        if converted is not None:
            rules.append(converted)

    if unsafe_keywords:
        details = "\n".join(unsafe_keywords)
        raise SystemExit(
            "Refusing to drop non-IP-prefix DOMAIN-KEYWORD rules:\n"
            f"{details}"
        )

    return dedupe_preserving_order(rules), skipped


def convert_anywhere_rule(rule_type: str, value: str, line_number: int, label: str) -> Rule | None:
    normalized_type = rule_type.strip()
    normalized_value = value.strip().lower()
    if not normalized_value:
        return None

    if normalized_type == "0":
        try:
            return ("0", str(ipaddress.IPv4Network(normalized_value, strict=False)))
        except ValueError as exc:
            raise SystemExit(f"{label}:{line_number}: invalid IPv4 CIDR {value} ({exc})") from exc
    if normalized_type == "1":
        try:
            return ("1", str(ipaddress.IPv6Network(normalized_value, strict=False)))
        except ValueError as exc:
            raise SystemExit(f"{label}:{line_number}: invalid IPv6 CIDR {value} ({exc})") from exc
    if normalized_type in {"2", "3"}:
        return (normalized_type, normalized_value)
    return None


def parse_anywhere_rules(text: str, label: str) -> list[Rule]:
    rules: list[Rule] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or "=" in line:
            continue
        parts = [part.strip() for part in line.split(",", 1)]
        if len(parts) != 2:
            continue
        converted = convert_anywhere_rule(parts[0], parts[1], line_number, label)
        if converted is not None:
            rules.append(converted)
    return dedupe_preserving_order(rules)


def validate_supplemental_rules(text: str) -> None:
    source_rules = set(parse_anywhere_rules(text, SUPPLEMENTAL_SOURCE_URL))
    missing = [
        f"{rule_type}, {value}"
        for (rule_type, value), _ in SUPPLEMENTAL_RULES
        if (rule_type, value) not in source_rules
    ]
    if missing:
        details = "\n".join(missing)
        raise SystemExit(
            "Supplemental WeChat rule(s) are missing from the supplemental source:\n"
            f"{details}"
        )


def build_rules(source_rules: list[Rule]) -> list[Rule]:
    rules = dedupe_preserving_order(source_rules)
    for supplemental, anchor in SUPPLEMENTAL_RULES:
        if supplemental in rules:
            continue
        try:
            anchor_index = rules.index(anchor)
        except ValueError:
            rules.append(supplemental)
        else:
            rules.insert(anchor_index + 1, supplemental)
    return rules


def output_last_updated(path: Path, rules: list[Rule]) -> str:
    if path.exists():
        text = path.read_text(encoding="utf-8")
        existing_rules = [
            tuple(part.strip() for part in line.split(",", 1))
            for line in text.splitlines()
            if re.fullmatch(r"[0-2], .+", line.strip())
        ]
        if existing_rules == rules:
            for line in text.splitlines():
                prefix = "# LAST-UPDATED: "
                if line.startswith(prefix):
                    return line.removeprefix(prefix).strip()
    return date.today().isoformat()


def render_rules(rules: list[Rule], last_updated: str) -> str:
    body = "\n".join(f"{rule_type}, {value}" for rule_type, value in rules)
    return (
        "# PURPOSE: Direct routing rules for WeChat core domains and IP ranges.\n"
        f"# LINK: {RAW_LINK}\n"
        f"# LAST-UPDATED: {last_updated}\n"
        "# SUGGESTED-ACTION: DIRECT\n"
        f"# RULES: {len(rules)}\n"
        "\n"
        "name = WeChat\n"
        f"{body}\n"
    )


def validate_output(text: str, expected_count: int) -> None:
    active_rules = [
        line for line in text.splitlines()
        if re.fullmatch(r"[0-2], .+", line.strip())
    ]
    if len(active_rules) != expected_count:
        raise SystemExit(f"RULES mismatch: header={expected_count}, actual={len(active_rules)}")

    for token in FORBIDDEN_OUTPUT_TOKENS:
        if token in text:
            raise SystemExit(f"Forbidden token found in output: {token}")


def write_output(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    source_rules, skipped = parse_rules(fetch_source())
    validate_supplemental_rules(fetch_supplemental_source())
    rules = build_rules(source_rules)
    rendered = render_rules(rules, output_last_updated(OUTPUT_PATH, rules))
    validate_output(rendered, len(rules))
    changed = write_output(OUTPUT_PATH, rendered)

    type_counts = Counter(rule_type for rule_type, _ in rules)
    print(f"{'wrote' if changed else 'unchanged'} {OUTPUT_PATH}")
    print(f"rules={len(rules)} type0={type_counts['0']} type1={type_counts['1']} type2={type_counts['2']}")
    print("skipped=" + ", ".join(f"{key}:{value}" for key, value in sorted(skipped.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())

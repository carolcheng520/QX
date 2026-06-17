#!/usr/bin/env python3
"""Generate a compact Anywhere WeChat routing rule set from Surge rules."""

from __future__ import annotations

import ipaddress
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path


SOURCE_URL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/WeChat/WeChat.list"
OUTPUT_PATH = Path(__file__).resolve().parents[1] / "rules" / "wechat.arrs"
RAW_LINK = "https://raw.githubusercontent.com/carolcheng520/anyrule/main/rules/wechat.arrs"

IPV4_PREFIX_RE = re.compile(r"^(?:\d{1,3}\.){2,3}$")
SUPPORTED_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
SKIPPED_TYPES = {"DOMAIN-KEYWORD", "IP-ASN", "USER-AGENT"}


def fetch_source() -> str:
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
        return response.read().decode("utf-8")


def is_ipv4_prefix_keyword(value: str) -> bool:
    if not IPV4_PREFIX_RE.fullmatch(value):
        return False
    octets = [part for part in value.split(".") if part]
    return all(0 <= int(octet) <= 255 for octet in octets)


def convert_rule(rule_type: str, value: str) -> tuple[str, str] | None:
    normalized = value.strip().lower()
    if not normalized:
        return None

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return ("2", normalized)
    if rule_type == "IP-CIDR":
        ipaddress.IPv4Network(normalized, strict=False)
        return ("0", normalized)
    if rule_type == "IP-CIDR6":
        ipaddress.IPv6Network(normalized, strict=False)
        return ("1", normalized)
    return None


def parse_rules(text: str) -> tuple[list[tuple[str, str]], Counter[str]]:
    rules: list[tuple[str, str]] = []
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

    deduped: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        if rule in seen:
            continue
        seen.add(rule)
        deduped.append(rule)

    return deduped, skipped


def render_rules(rules: list[tuple[str, str]]) -> str:
    body = "\n".join(f"{rule_type}, {value}" for rule_type, value in rules)
    return (
        "# PURPOSE: Direct routing rules for WeChat core domains and IP ranges.\n"
        f"# LINK: {RAW_LINK}\n"
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

    forbidden = ["3,", "DOMAIN-KEYWORD", "IP-ASN", "USER-AGENT", "no-resolve"]
    for token in forbidden:
        if token in text:
            raise SystemExit(f"Forbidden token found in output: {token}")


def main() -> int:
    rules, skipped = parse_rules(fetch_source())
    rendered = render_rules(rules)
    validate_output(rendered, len(rules))
    OUTPUT_PATH.write_text(rendered, encoding="utf-8")

    type_counts = Counter(rule_type for rule_type, _ in rules)
    print(f"wrote {OUTPUT_PATH}")
    print(f"rules={len(rules)} type0={type_counts['0']} type1={type_counts['1']} type2={type_counts['2']}")
    print("skipped=" + ", ".join(f"{key}:{value}" for key, value in sorted(skipped.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())

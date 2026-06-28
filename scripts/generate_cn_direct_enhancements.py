#!/usr/bin/env python3
"""Generate filtered China direct-routing enhancement rule sets."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import sqlite3
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_DB = REPO_ROOT.parent / "Anywhere" / "Shared" / "DataStore" / "Rules.db"

GEOSITE_URL = (
    "https://raw.githubusercontent.com/chikacya/anywhere-rules/"
    "refs/heads/main/rules/common/Geosite_CN.arrs"
)
GEOIP_URL = (
    "https://raw.githubusercontent.com/chikacya/anywhere-rules/"
    "refs/heads/main/rules/common/GeoIP_CN.arrs"
)
LAN_URL = "https://raw.githubusercontent.com/chikacya/anywhere-rules/main/rules/common/Lan.arrs"

GEOSITE_OUTPUT = REPO_ROOT / "rules" / "geosite-cn-direct-delta.arrs"
GEOIP_OUTPUT = REPO_ROOT / "rules" / "geoip-cn-ipv6.arrs"
GEOSITE_RAW_LINK = (
    "https://raw.githubusercontent.com/carolcheng520/anyrule/main/"
    "rules/geosite-cn-direct-delta.arrs"
)
GEOIP_RAW_LINK = (
    "https://raw.githubusercontent.com/carolcheng520/anyrule/main/"
    "rules/geoip-cn-ipv6.arrs"
)

DIRECT_BASELINE_FILES = [
    "wechat.arrs",
    "10086.arrs",
    "bocchat.arrs",
    "eastmoney.arrs",
    "finance-apps.arrs",
    "direct-app.arrs",
    "portfolio.arrs",
]


@dataclass(frozen=True)
class SourceText:
    text: str
    sha256: str


Rule = tuple[int, str]


def read_source(location: str) -> SourceText:
    if location.startswith(("http://", "https://")):
        with urllib.request.urlopen(location, timeout=30) as response:
            data = response.read()
    else:
        data = Path(location).read_bytes()
    return SourceText(data.decode("utf-8"), hashlib.sha256(data).hexdigest())


def canonical_domain(value: str) -> str:
    labels = [label for label in value.strip().lower().split(".") if label]
    return ".".join(labels)


def canonical_cidr(rule_type: int, value: str) -> str:
    raw = value.strip()
    if rule_type == 0:
        if "/" not in raw:
            raw += "/32"
        return str(ipaddress.IPv4Network(raw, strict=False))
    if "/" not in raw:
        raw += "/128"
    return str(ipaddress.IPv6Network(raw, strict=False))


def parse_arrs(text: str, source_name: str) -> list[Rule]:
    rules: list[Rule] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "=" in line:
            continue
        if "," not in line:
            raise SystemExit(f"{source_name}:{line_number}: invalid rule line: {line}")

        raw_type, raw_value = line.split(",", 1)
        try:
            rule_type = int(raw_type.strip())
        except ValueError as exc:
            raise SystemExit(f"{source_name}:{line_number}: invalid rule type: {line}") from exc

        value = raw_value.strip()
        if rule_type not in {0, 1, 2, 3} or not value:
            raise SystemExit(f"{source_name}:{line_number}: unsupported or empty rule: {line}")

        if rule_type in {0, 1}:
            rules.append((rule_type, canonical_cidr(rule_type, value)))
        else:
            rules.append((rule_type, canonical_domain(value)))
    return rules


def load_db_rules(rules_db: Path, source: str) -> list[Rule]:
    with sqlite3.connect(rules_db) as db:
        rows = db.execute(
            "SELECT type, value FROM rules WHERE source = ? ORDER BY rowid",
            (source,),
        ).fetchall()

    rules: list[Rule] = []
    for rule_type, value in rows:
        if rule_type in {0, 1}:
            rules.append((rule_type, canonical_cidr(rule_type, value)))
        elif rule_type in {2, 3}:
            rules.append((rule_type, canonical_domain(value)))
    return rules


def domain_is_covered(domain: str, suffixes: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))


def direct_baseline_sources(lan_source: str) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    for filename in DIRECT_BASELINE_FILES:
        sources.append((filename, str(REPO_ROOT / "rules" / filename)))
    sources.insert(1, ("Lan.arrs", lan_source))
    return sources


def load_direct_baseline_rules(lan_source: str) -> list[Rule]:
    rules: list[Rule] = []
    for name, location in direct_baseline_sources(lan_source):
        source = read_source(location)
        rules.extend(parse_arrs(source.text, name))
    return rules


def dedupe_preserving_order(rules: list[Rule]) -> list[Rule]:
    seen: set[Rule] = set()
    output: list[Rule] = []
    for rule in rules:
        if rule in seen:
            continue
        seen.add(rule)
        output.append(rule)
    return output


def generate_geosite_delta(
    geosite_rules: list[Rule],
    builtin_cn_rules: list[Rule],
    direct_rules: list[Rule],
    adblock_rules: list[Rule],
) -> tuple[list[Rule], Counter[str]]:
    baseline_suffixes = {
        value for rule_type, value in builtin_cn_rules + direct_rules if rule_type == 2
    }
    adblock_suffixes = {value for rule_type, value in adblock_rules if rule_type == 2}

    output: list[Rule] = []
    skipped: Counter[str] = Counter()
    for rule_type, value in geosite_rules:
        if rule_type != 2:
            skipped[f"type{rule_type}"] += 1
            continue
        if domain_is_covered(value, baseline_suffixes):
            skipped["baseline-covered"] += 1
            continue
        if domain_is_covered(value, adblock_suffixes):
            skipped["adblock-covered"] += 1
            continue
        output.append((rule_type, value))

    return dedupe_preserving_order(output), skipped


def generate_geoip_ipv6(geoip_rules: list[Rule]) -> tuple[list[Rule], Counter[str]]:
    output: list[Rule] = []
    skipped: Counter[str] = Counter()
    for rule_type, value in geoip_rules:
        if rule_type == 1:
            output.append((rule_type, value))
        else:
            skipped[f"type{rule_type}"] += 1
    return dedupe_preserving_order(output), skipped


def render_rule_file(
    *,
    purpose: str,
    raw_link: str,
    name: str,
    rules: list[Rule],
    source_url: str,
    source_sha256: str,
    skipped: Counter[str],
) -> str:
    skipped_text = ", ".join(f"{key}={value}" for key, value in sorted(skipped.items()))
    body = "\n".join(f"{rule_type}, {value}" for rule_type, value in rules)
    return (
        f"# PURPOSE: {purpose}\n"
        f"# LINK: {raw_link}\n"
        f"# LAST-UPDATED: {date.today().isoformat()}\n"
        "# SUGGESTED-ACTION: DIRECT\n"
        f"# RULES: {len(rules)}\n"
        f"# SOURCE: {source_url}\n"
        f"# SOURCE-SHA256: {source_sha256}\n"
        f"# GENERATED-BY: scripts/generate_cn_direct_enhancements.py\n"
        f"# SKIPPED: {skipped_text or 'none'}\n"
        "\n"
        f"name = {name}\n"
        f"{body}\n"
    )


def validate_geosite_delta(
    rules: list[Rule],
    builtin_cn_rules: list[Rule],
    direct_rules: list[Rule],
    adblock_rules: list[Rule],
) -> None:
    if any(rule_type != 2 for rule_type, _ in rules):
        raise SystemExit("Geosite delta contains a non-domain-suffix rule")

    baseline_suffixes = {
        value for rule_type, value in builtin_cn_rules + direct_rules if rule_type == 2
    }
    adblock_suffixes = {value for rule_type, value in adblock_rules if rule_type == 2}

    baseline_hits = [
        value for _, value in rules if domain_is_covered(value, baseline_suffixes)
    ]
    adblock_hits = [
        value for _, value in rules if domain_is_covered(value, adblock_suffixes)
    ]
    if baseline_hits:
        raise SystemExit("Geosite delta still has baseline-covered domains: " + ", ".join(baseline_hits[:10]))
    if adblock_hits:
        raise SystemExit("Geosite delta still has ADBlock-covered domains: " + ", ".join(adblock_hits[:10]))


def validate_geoip_ipv6(rules: list[Rule]) -> None:
    if any(rule_type != 1 for rule_type, _ in rules):
        raise SystemExit("GeoIP IPv6 output contains non-IPv6 rules")
    for _, value in rules:
        ipaddress.IPv6Network(value, strict=False)


def write_output(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-db", type=Path, default=DEFAULT_RULES_DB)
    parser.add_argument("--geosite-source", default=GEOSITE_URL)
    parser.add_argument("--geoip-source", default=GEOIP_URL)
    parser.add_argument("--lan-source", default=LAN_URL)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.rules_db.exists():
        raise SystemExit(f"Rules.db not found: {args.rules_db}")

    geosite_source = read_source(args.geosite_source)
    geoip_source = read_source(args.geoip_source)

    builtin_cn_rules = load_db_rules(args.rules_db, "CN")
    adblock_rules = load_db_rules(args.rules_db, "ADBlock")
    direct_rules = load_direct_baseline_rules(args.lan_source)
    geosite_rules = parse_arrs(geosite_source.text, args.geosite_source)
    geoip_rules = parse_arrs(geoip_source.text, args.geoip_source)

    geosite_delta, geosite_skipped = generate_geosite_delta(
        geosite_rules,
        builtin_cn_rules,
        direct_rules,
        adblock_rules,
    )
    geoip_ipv6, geoip_skipped = generate_geoip_ipv6(geoip_rules)

    validate_geosite_delta(geosite_delta, builtin_cn_rules, direct_rules, adblock_rules)
    validate_geoip_ipv6(geoip_ipv6)

    geosite_text = render_rule_file(
        purpose="Filtered China geosite direct-routing delta not covered by built-in CN, existing direct rules, or ADBlock.",
        raw_link=GEOSITE_RAW_LINK,
        name="Geosite CN Direct Delta",
        rules=geosite_delta,
        source_url=GEOSITE_URL,
        source_sha256=geosite_source.sha256,
        skipped=geosite_skipped,
    )
    geoip_text = render_rule_file(
        purpose="China IPv6 direct-routing CIDR rules generated from GeoIP_CN.",
        raw_link=GEOIP_RAW_LINK,
        name="GeoIP CN IPv6",
        rules=geoip_ipv6,
        source_url=GEOIP_URL,
        source_sha256=geoip_source.sha256,
        skipped=geoip_skipped,
    )

    write_output(GEOSITE_OUTPUT, geosite_text)
    write_output(GEOIP_OUTPUT, geoip_text)

    geosite_counts = Counter(rule_type for rule_type, _ in geosite_delta)
    geoip_counts = Counter(rule_type for rule_type, _ in geoip_ipv6)
    print(f"wrote {GEOSITE_OUTPUT}")
    print(f"geosite_rules={len(geosite_delta)} type2={geosite_counts[2]} skipped={dict(sorted(geosite_skipped.items()))}")
    print(f"wrote {GEOIP_OUTPUT}")
    print(f"geoip_rules={len(geoip_ipv6)} type1={geoip_counts[1]} skipped={dict(sorted(geoip_skipped.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

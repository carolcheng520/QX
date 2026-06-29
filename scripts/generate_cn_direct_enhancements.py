#!/usr/bin/env python3
"""Generate filtered China direct-routing enhancement rule sets."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path


sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_DB = REPO_ROOT.parent / "Anywhere" / "Shared" / "DataStore" / "Rules.db"
DEFAULT_ANYWHERE_RULES_ROOT = REPO_ROOT.parent / "anywhere-rules"
ANYRULE_RULES_ROOT = REPO_ROOT / "rules"

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

GEOSITE_SOURCE_NAME = "Geosite_CN.arrs"
GEOIP_SOURCE_NAME = "GeoIP_CN.arrs"
LAN_SOURCE_NAME = "Lan.arrs"

DIRECT_BASELINE_FILES = [
    "wechat.arrs",
    "10086.arrs",
    "bocchat.arrs",
    "eastmoney.arrs",
    "finance-apps.arrs",
    "direct-app.arrs",
    "portfolio.arrs",
]
MITM_REJECT_FILES = [
    "AmapReject.arrs",
    "BilibiliReject.arrs",
    "WeiboReject.arrs",
    "XiaohongshuReject.arrs",
]
LOCAL_REJECT_FILES = [
    "wechat-ads.arrs",
]


@dataclass(frozen=True)
class SourceText:
    text: str
    sha256: str
    location: Path
    label: str


@dataclass(frozen=True)
class RuleSources:
    geosite: SourceText
    geoip: SourceText
    direct: list[tuple[str, SourceText]]
    mitm_reject: list[tuple[str, SourceText]]


@dataclass(frozen=True)
class RuleContext:
    sources: RuleSources
    builtin_cn_rules: list[Rule]
    adblock_rules: list[Rule]
    direct_rules: list[Rule]
    mitm_reject_rules: list[Rule]
    mitm_reject_skipped: Counter[str]
    geosite_rules: list[Rule]
    geoip_rules: list[Rule]


@dataclass(frozen=True)
class GeneratedFile:
    path: Path
    text: str
    rules: list[Rule]
    skipped: Counter[str]


@dataclass(frozen=True)
class GenerationResult:
    geosite: GeneratedFile
    geoip: GeneratedFile
    mitm_reject_rules: list[Rule]


Rule = tuple[int, str]


def local_path_arg(value: str) -> Path:
    if value.startswith(("http://", "https://")):
        raise argparse.ArgumentTypeError("remote URLs are not supported; use a local file path")
    return Path(value).expanduser()


def read_source(location: Path, label: str) -> SourceText:
    data = location.read_bytes()
    return SourceText(data.decode("utf-8"), hashlib.sha256(data).hexdigest(), location, label)


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


def domain_has_suffix(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def domain_conflicts_with_suffixes(domain: str, suffixes: set[str]) -> bool:
    return any(
        domain_has_suffix(domain, suffix) or domain_has_suffix(suffix, domain)
        for suffix in suffixes
    )


def default_geosite_source(anywhere_rules_root: Path) -> Path:
    return anywhere_rules_root / "rules" / "common" / GEOSITE_SOURCE_NAME


def default_geoip_source(anywhere_rules_root: Path) -> Path:
    return anywhere_rules_root / "rules" / "common" / GEOIP_SOURCE_NAME


def default_lan_source(anywhere_rules_root: Path) -> Path:
    return anywhere_rules_root / "rules" / "common" / LAN_SOURCE_NAME


def direct_baseline_sources(lan_source: Path) -> list[tuple[str, Path]]:
    sources: list[tuple[str, Path]] = []
    for filename in DIRECT_BASELINE_FILES:
        sources.append((filename, ANYRULE_RULES_ROOT / filename))
    sources.insert(1, ("Lan.arrs", lan_source))
    return sources


def mitm_reject_sources(anywhere_rules_root: Path) -> list[tuple[str, Path]]:
    sources = [
        (filename, anywhere_rules_root / "mitm" / filename)
        for filename in MITM_REJECT_FILES
    ]
    sources.extend(
        (filename, ANYRULE_RULES_ROOT / filename)
        for filename in LOCAL_REJECT_FILES
    )
    return sources


def require_sources(paths: list[tuple[str, Path]]) -> None:
    remote = [
        (name, path)
        for name, path in paths
        if str(path).startswith(("http:/", "https:/"))
    ]
    if remote:
        details = "\n".join(f"- {name}: {path}" for name, path in remote)
        raise SystemExit("Remote input source(s) are not supported:\n" + details)

    missing = [(name, path) for name, path in paths if not path.is_file()]
    if not missing:
        return
    details = "\n".join(f"- {name}: {path}" for name, path in missing)
    raise SystemExit("Missing input source file(s):\n" + details)


def load_inputs(args: argparse.Namespace) -> RuleSources:
    anywhere_rules_root = args.anywhere_rules_root
    geosite_source = args.geosite_source or default_geosite_source(anywhere_rules_root)
    geoip_source = args.geoip_source or default_geoip_source(anywhere_rules_root)
    lan_source = args.lan_source or default_lan_source(anywhere_rules_root)
    direct_paths = direct_baseline_sources(lan_source)
    mitm_reject_paths = mitm_reject_sources(anywhere_rules_root)
    require_sources(
        [(GEOSITE_SOURCE_NAME, geosite_source), (GEOIP_SOURCE_NAME, geoip_source)]
        + direct_paths
        + mitm_reject_paths
    )
    direct_sources = [
        (
            name,
            read_source(
                location,
                f"anywhere-rules/rules/common/{name}"
                if name == LAN_SOURCE_NAME
                else f"anyrule/rules/{name}",
            ),
        )
        for name, location in direct_paths
    ]
    mitm_reject_source_texts = [
        (
            name,
            read_source(
                location,
                f"anyrule/rules/{name}"
                if name in LOCAL_REJECT_FILES
                else f"anywhere-rules/mitm/{name}",
            ),
        )
        for name, location in mitm_reject_paths
    ]
    return RuleSources(
        geosite=read_source(geosite_source, f"anywhere-rules/rules/common/{GEOSITE_SOURCE_NAME}"),
        geoip=read_source(geoip_source, f"anywhere-rules/rules/common/{GEOIP_SOURCE_NAME}"),
        direct=direct_sources,
        mitm_reject=mitm_reject_source_texts,
    )


def load_direct_baseline_rules(sources: list[tuple[str, SourceText]]) -> list[Rule]:
    rules: list[Rule] = []
    for name, source in sources:
        rules.extend(parse_arrs(source.text, name))
    return rules


def load_mitm_reject_rules(sources: list[tuple[str, SourceText]]) -> tuple[list[Rule], Counter[str]]:
    rules: list[Rule] = []
    skipped: Counter[str] = Counter()
    for name, source in sources:
        for rule_type, value in parse_arrs(source.text, name):
            if rule_type == 2:
                rules.append((rule_type, value))
            else:
                skipped[f"mitm-reject-type{rule_type}"] += 1
    return dedupe_preserving_order(rules), skipped


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
    mitm_reject_rules: list[Rule],
) -> tuple[list[Rule], Counter[str]]:
    baseline_suffixes = {
        value for rule_type, value in builtin_cn_rules + direct_rules if rule_type == 2
    }
    adblock_suffixes = {value for rule_type, value in adblock_rules if rule_type == 2}
    mitm_reject_suffixes = {
        value for rule_type, value in mitm_reject_rules if rule_type == 2
    }

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
        if domain_conflicts_with_suffixes(value, mitm_reject_suffixes):
            skipped["mitm-reject-covered"] += 1
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


def output_last_updated(path: Path, rules: list[Rule]) -> str:
    if path.exists():
        text = path.read_text(encoding="utf-8")
        if parse_arrs(text, str(path)) == rules:
            for line in text.splitlines():
                prefix = "# LAST-UPDATED: "
                if line.startswith(prefix):
                    return line.removeprefix(prefix).strip()
    return date.today().isoformat()


def render_rule_file(
    *,
    purpose: str,
    raw_link: str,
    last_updated: str,
    name: str,
    rules: list[Rule],
    source_label: str,
    source_sha256: str,
    skipped: Counter[str],
    extra_header_lines: list[str] | None = None,
) -> str:
    skipped_text = ", ".join(f"{key}={value}" for key, value in sorted(skipped.items()))
    extra_header = "".join(f"{line}\n" for line in extra_header_lines or [])
    body = "\n".join(f"{rule_type}, {value}" for rule_type, value in rules)
    return (
        f"# PURPOSE: {purpose}\n"
        f"# LINK: {raw_link}\n"
        f"# LAST-UPDATED: {last_updated}\n"
        "# SUGGESTED-ACTION: DIRECT\n"
        f"# RULES: {len(rules)}\n"
        f"# SOURCE: {source_label}\n"
        f"# SOURCE-SHA256: {source_sha256}\n"
        f"{extra_header}"
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
    mitm_reject_rules: list[Rule],
) -> None:
    if any(rule_type != 2 for rule_type, _ in rules):
        raise SystemExit("Geosite delta contains a non-domain-suffix rule")

    baseline_suffixes = {
        value for rule_type, value in builtin_cn_rules + direct_rules if rule_type == 2
    }
    adblock_suffixes = {value for rule_type, value in adblock_rules if rule_type == 2}
    mitm_reject_suffixes = {
        value for rule_type, value in mitm_reject_rules if rule_type == 2
    }

    baseline_hits = [
        value for _, value in rules if domain_is_covered(value, baseline_suffixes)
    ]
    adblock_hits = [
        value for _, value in rules if domain_is_covered(value, adblock_suffixes)
    ]
    mitm_reject_hits = [
        value for _, value in rules if domain_conflicts_with_suffixes(value, mitm_reject_suffixes)
    ]
    if baseline_hits:
        raise SystemExit("Geosite delta still has baseline-covered domains: " + ", ".join(baseline_hits[:10]))
    if adblock_hits:
        raise SystemExit("Geosite delta still has ADBlock-covered domains: " + ", ".join(adblock_hits[:10]))
    if mitm_reject_hits:
        raise SystemExit("Geosite delta still conflicts with MITM reject domains: " + ", ".join(mitm_reject_hits[:10]))


def validate_geoip_ipv6(rules: list[Rule]) -> None:
    if any(rule_type != 1 for rule_type, _ in rules):
        raise SystemExit("GeoIP IPv6 output contains non-IPv6 rules")
    for _, value in rules:
        ipaddress.IPv6Network(value, strict=False)


def write_output(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def load_rule_context(args: argparse.Namespace) -> RuleContext:
    if not args.rules_db.exists():
        raise SystemExit(f"Rules.db not found: {args.rules_db}")

    sources = load_inputs(args)
    direct_rules = load_direct_baseline_rules(sources.direct)
    mitm_reject_rules, mitm_reject_skipped = load_mitm_reject_rules(sources.mitm_reject)
    return RuleContext(
        sources=sources,
        builtin_cn_rules=load_db_rules(args.rules_db, "CN"),
        adblock_rules=load_db_rules(args.rules_db, "ADBlock"),
        direct_rules=direct_rules,
        mitm_reject_rules=mitm_reject_rules,
        mitm_reject_skipped=mitm_reject_skipped,
        geosite_rules=parse_arrs(sources.geosite.text, sources.geosite.label),
        geoip_rules=parse_arrs(sources.geoip.text, sources.geoip.label),
    )


def build_generation_result(context: RuleContext) -> GenerationResult:
    geosite_delta, geosite_skipped = generate_geosite_delta(
        context.geosite_rules,
        context.builtin_cn_rules,
        context.direct_rules,
        context.adblock_rules,
        context.mitm_reject_rules,
    )
    geosite_skipped.update(context.mitm_reject_skipped)
    geoip_ipv6, geoip_skipped = generate_geoip_ipv6(context.geoip_rules)

    validate_geosite_delta(
        geosite_delta,
        context.builtin_cn_rules,
        context.direct_rules,
        context.adblock_rules,
        context.mitm_reject_rules,
    )
    validate_geoip_ipv6(geoip_ipv6)

    geosite_text = render_rule_file(
        purpose="Filtered China geosite direct-routing delta not covered by built-in CN, existing direct rules, ADBlock, or MITM reject routing rules.",
        raw_link=GEOSITE_RAW_LINK,
        last_updated=output_last_updated(GEOSITE_OUTPUT, geosite_delta),
        name="Geosite CN Direct Delta",
        rules=geosite_delta,
        source_label=context.sources.geosite.label,
        source_sha256=context.sources.geosite.sha256,
        skipped=geosite_skipped,
        extra_header_lines=[
            "# EXCLUDED-REJECT-SOURCES:",
            *[
                f"# - {name}: {source.label}"
                for name, source in context.sources.mitm_reject
            ],
        ],
    )
    geoip_text = render_rule_file(
        purpose="China IPv6 direct-routing CIDR rules generated from GeoIP_CN.",
        raw_link=GEOIP_RAW_LINK,
        last_updated=output_last_updated(GEOIP_OUTPUT, geoip_ipv6),
        name="GeoIP CN IPv6",
        rules=geoip_ipv6,
        source_label=context.sources.geoip.label,
        source_sha256=context.sources.geoip.sha256,
        skipped=geoip_skipped,
    )
    return GenerationResult(
        geosite=GeneratedFile(GEOSITE_OUTPUT, geosite_text, geosite_delta, geosite_skipped),
        geoip=GeneratedFile(GEOIP_OUTPUT, geoip_text, geoip_ipv6, geoip_skipped),
        mitm_reject_rules=context.mitm_reject_rules,
    )


def write_generation_result(result: GenerationResult) -> tuple[bool, bool]:
    return (
        write_output(result.geosite.path, result.geosite.text),
        write_output(result.geoip.path, result.geoip.text),
    )


def print_summary(result: GenerationResult, wrote_geosite: bool, wrote_geoip: bool) -> None:
    geosite_counts = Counter(rule_type for rule_type, _ in result.geosite.rules)
    geoip_counts = Counter(rule_type for rule_type, _ in result.geoip.rules)
    print(f"{'wrote' if wrote_geosite else 'unchanged'} {result.geosite.path}")
    print(
        f"geosite_rules={len(result.geosite.rules)} "
        f"type2={geosite_counts[2]} "
        f"skipped={dict(sorted(result.geosite.skipped.items()))}"
    )
    print(
        f"mitm_reject_rules={len(result.mitm_reject_rules)} "
        f"type2={Counter(rule_type for rule_type, _ in result.mitm_reject_rules)[2]}"
    )
    print(f"{'wrote' if wrote_geoip else 'unchanged'} {result.geoip.path}")
    print(
        f"geoip_rules={len(result.geoip.rules)} "
        f"type1={geoip_counts[1]} "
        f"skipped={dict(sorted(result.geoip.skipped.items()))}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-db", type=local_path_arg, default=DEFAULT_RULES_DB)
    parser.add_argument("--anywhere-rules-root", type=local_path_arg, default=DEFAULT_ANYWHERE_RULES_ROOT)
    parser.add_argument("--geosite-source", type=local_path_arg)
    parser.add_argument("--geoip-source", type=local_path_arg)
    parser.add_argument("--lan-source", type=local_path_arg)
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    result = build_generation_result(load_rule_context(args))
    wrote_geosite, wrote_geoip = write_generation_result(result)
    print_summary(result, wrote_geosite, wrote_geoip)
    return 0


if __name__ == "__main__":
    sys.exit(main())

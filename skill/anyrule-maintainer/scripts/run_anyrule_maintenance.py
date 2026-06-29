#!/usr/bin/env python3
"""Run the guarded AnyRule periodic maintenance workflow."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


MAIN_BRANCH = "main"
WECHAT_COMMIT = "Update WeChat Anywhere rules"
CN_COMMIT = "Update CN direct enhancement rules"
WECHAT_ALLOWED = {"rules/wechat.arrs"}
CN_ALLOWED = {"rules/geosite-cn-direct-delta.arrs", "rules/geoip-cn-ipv6.arrs"}
SKILL_NAME = "anyrule-maintainer"
SKILL_FILES = {
    "skill/install_anyrule_maintainer.py",
    "skill/anyrule-maintainer/SKILL.md",
    "skill/anyrule-maintainer/agents/openai.yaml",
    "skill/anyrule-maintainer/scripts/run_anyrule_maintenance.py",
}
ABSOLUTE_PATH_RE = re.compile("/" + "Users" + r"/[^\s`'\"]+")


@dataclass(frozen=True)
class RepoSpec:
    name: str
    path: Path
    origin_url: str
    allow_behind: bool = False


class MaintenanceError(Exception):
    pass


def anyrule_root() -> Path:
    return Path(__file__).resolve().parents[3]


def repo_specs(root: Path) -> list[RepoSpec]:
    parent = root.parent
    return [
        RepoSpec("anyrule", root, "git@github.com:carolcheng520/anyrule.git"),
        RepoSpec("anywhere-rules", parent / "anywhere-rules", "https://github.com/chikacya/anywhere-rules.git", True),
        RepoSpec("Anywhere", parent / "Anywhere", "https://github.com/NodePassProject/Anywhere.git", True),
    ]


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise MaintenanceError(f"{cwd}: {' '.join(cmd)} failed with exit code {result.returncode}")
    return result


def run_quiet(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)


def git(repo: RepoSpec, args: list[str]) -> str:
    return run(["git", *args], repo.path).stdout.strip()


def ensure_repo_shape(repo: RepoSpec) -> None:
    if not repo.path.is_dir():
        raise MaintenanceError(f"{repo.name}: missing repository directory: {repo.path}")

    top_level = Path(git(repo, ["rev-parse", "--show-toplevel"])).resolve()
    if top_level != repo.path.resolve():
        raise MaintenanceError(f"{repo.name}: expected repo root {repo.path}, found {top_level}")

    branch = git(repo, ["branch", "--show-current"])
    if branch != MAIN_BRANCH:
        raise MaintenanceError(f"{repo.name}: expected branch {MAIN_BRANCH}, found {branch or 'detached HEAD'}")

    origin = git(repo, ["remote", "get-url", "origin"])
    if origin != repo.origin_url:
        raise MaintenanceError(f"{repo.name}: expected origin {repo.origin_url}, found {origin}")


def status_paths(repo: RepoSpec) -> set[str]:
    output = git(repo, ["status", "--porcelain"])
    paths: set[str] = set()
    for line in output.splitlines():
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.add(path)
    return paths


def require_clean(repo: RepoSpec) -> None:
    paths = status_paths(repo)
    if paths:
        preview = "\n".join(f"- {path}" for path in sorted(paths))
        raise MaintenanceError(f"{repo.name}: worktree is not clean:\n{preview}")


def divergence(repo: RepoSpec) -> tuple[int, int]:
    git(repo, ["fetch", "origin", MAIN_BRANCH])
    output = git(repo, ["rev-list", "--left-right", "--count", f"HEAD...origin/{MAIN_BRANCH}"])
    parts = output.split()
    if len(parts) != 2:
        raise MaintenanceError(f"{repo.name}: unexpected divergence output: {output}")
    return int(parts[0]), int(parts[1])


def require_sync_state(repo: RepoSpec) -> None:
    ahead, behind = divergence(repo)
    if ahead:
        raise MaintenanceError(f"{repo.name}: local branch has {ahead} unpushed commit(s)")
    if behind and not repo.allow_behind:
        raise MaintenanceError(f"{repo.name}: local branch is {behind} commit(s) behind origin/{MAIN_BRANCH}")


def validate_environment(repos: list[RepoSpec]) -> None:
    for repo in repos:
        ensure_repo_shape(repo)
        require_clean(repo)
        require_sync_state(repo)


def run_preflight_tests(root: Path) -> None:
    run(["python3", "scripts/test_update_wechat_arrs.py"], root)
    run(["python3", "scripts/test_generate_cn_direct_enhancements.py"], root)
    run(["python3", "scripts/sync_github_repos.py", "--self-test"], root)


def codex_skills_dir() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    base = Path(codex_home).expanduser() if codex_home else Path.home() / ".codex"
    return base / "skills"


def print_review(label: str, ok: bool, detail: str) -> int:
    status = "PASS" if ok else "FAIL"
    print(f"{status}: {label} - {detail}")
    return 0 if ok else 1


def print_notice(label: str, detail: str) -> None:
    print(f"INFO: {label} - {detail}")


def skill_frontmatter_is_valid(skill_md: Path) -> bool:
    text = skill_md.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not match:
        return False
    frontmatter: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ": " not in line:
            return False
        key, value = line.split(": ", 1)
        frontmatter[key] = value
    name = frontmatter.get("name", "")
    description = frontmatter.get("description", "")
    return (
        set(frontmatter) == {"name", "description"}
        and name == SKILL_NAME
        and re.fullmatch(r"[a-z0-9-]+", name) is not None
        and bool(description.strip())
        and len(description) <= 1024
        and "<" not in description
        and ">" not in description
    )


def adversarial_check(root: Path) -> int:
    failures = 0
    skill_dir = root / "skill" / SKILL_NAME

    missing = [path for path in sorted(SKILL_FILES) if not (root / path).is_file()]
    failures += print_review(
        "required files",
        not missing,
        "all expected skill files exist" if not missing else ", ".join(missing),
    )

    tracked_missing: list[str] = []
    for path in sorted(SKILL_FILES):
        result = run_quiet(["git", "ls-files", "--error-unmatch", path], root)
        if result.returncode != 0:
            tracked_missing.append(path)
    failures += print_review(
        "git tracking",
        not tracked_missing,
        "all skill files are tracked" if not tracked_missing else "untracked: " + ", ".join(tracked_missing),
    )

    skill_md = skill_dir / "SKILL.md"
    failures += print_review(
        "skill frontmatter",
        skill_md.is_file() and skill_frontmatter_is_valid(skill_md),
        "name and description are valid",
    )

    link = codex_skills_dir() / SKILL_NAME
    if link.exists() or link.is_symlink():
        link_ok = link.is_symlink() and link.resolve() == skill_dir.resolve()
        link_detail = f"{link} -> {link.resolve()}" if link.is_symlink() else f"{link} is not a symlink"
        failures += print_review("Codex symlink", link_ok, link_detail)
    else:
        failures += print_review("Codex symlink", True, "not installed in this environment")

    hardcoded_hits: list[str] = []
    for path in sorted(SKILL_FILES):
        file_path = root / path
        if not file_path.is_file():
            continue
        text = file_path.read_text(encoding="utf-8")
        if ABSOLUTE_PATH_RE.search(text):
            hardcoded_hits.append(path)
    failures += print_review(
        "portable paths",
        not hardcoded_hits,
        "no machine-specific user-home paths in skill files" if not hardcoded_hits else ", ".join(hardcoded_hits),
    )

    yaml_check = run_quiet(["python3", "-c", "import yaml"], root)
    print_notice(
        "quick_validate dependency",
        "PyYAML is available" if yaml_check.returncode == 0 else "PyYAML is unavailable; manual frontmatter validation is sufficient",
    )

    return failures


def verify_remote_head(repo: RepoSpec) -> None:
    local = git(repo, ["rev-parse", "HEAD"])
    remote_output = git(repo, ["ls-remote", "--heads", "origin", MAIN_BRANCH])
    fields = remote_output.split()
    if len(fields) < 2:
        raise MaintenanceError(f"{repo.name}: origin/{MAIN_BRANCH} was not found by ls-remote")
    remote = fields[0]
    if remote != local:
        raise MaintenanceError(f"{repo.name}: remote main {remote} does not match local HEAD {local}")


def commit_allowed_changes(repo: RepoSpec, allowed: set[str], message: str) -> bool:
    paths = status_paths(repo)
    if not paths:
        print(f"{repo.name}: no changes for {message!r}")
        return False

    unexpected = paths - allowed
    if unexpected:
        details = "\n".join(f"- {path}" for path in sorted(unexpected))
        raise MaintenanceError(f"{repo.name}: unexpected changed path(s):\n{details}")

    git(repo, ["add", "--", *sorted(paths)])
    git(repo, ["commit", "-m", message])
    return True


def push_and_verify(repo: RepoSpec) -> None:
    git(repo, ["push", "origin", MAIN_BRANCH])
    verify_remote_head(repo)


def verify_all_synced(repos: list[RepoSpec]) -> None:
    for repo in repos:
        require_clean(repo)
        ahead, behind = divergence(repo)
        if (ahead, behind) != (0, 0):
            raise MaintenanceError(f"{repo.name}: final sync failed, ahead={ahead} behind={behind}")


def run_workflow(root: Path) -> None:
    anyrule = RepoSpec("anyrule", root, "git@github.com:carolcheng520/anyrule.git")

    run(["python3", "scripts/update_wechat_arrs.py"], root)
    if commit_allowed_changes(anyrule, WECHAT_ALLOWED, WECHAT_COMMIT):
        push_and_verify(anyrule)
    else:
        verify_remote_head(anyrule)

    run(["python3", "scripts/sync_github_repos.py"], root)
    verify_all_synced(repo_specs(root))

    run(["python3", "scripts/generate_cn_direct_enhancements.py"], root)
    if commit_allowed_changes(anyrule, CN_ALLOWED, CN_COMMIT):
        push_and_verify(anyrule)
    else:
        verify_remote_head(anyrule)

    verify_all_synced(repo_specs(root))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--adversarial-check",
        action="store_true",
        help="review skill packaging and portability assumptions without generating, committing, or pushing",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="validate repositories and tests without generating, committing, or pushing rule updates",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = anyrule_root()
    repos = repo_specs(root)

    try:
        if args.adversarial_check:
            failures = adversarial_check(root)
            if failures:
                raise MaintenanceError(f"adversarial check found {failures} issue(s)")
            print("Adversarial check passed.")
            return 0
        validate_environment(repos)
        run_preflight_tests(root)
        if args.check_only:
            print("Check-only validation passed.")
            return 0
        run_workflow(root)
    except MaintenanceError as exc:
        print(f"Maintenance failed: {exc}", file=sys.stderr)
        return 1

    print("AnyRule maintenance completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

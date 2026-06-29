#!/usr/bin/env python3
"""Safely fast-forward the local Anywhere-related GitHub repositories."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


MAIN_BRANCH = "main"


@dataclass(frozen=True)
class RepoSpec:
    name: str
    path: Path
    origin_url: str


@dataclass(frozen=True)
class SyncPlan:
    repo: RepoSpec
    ahead: int
    behind: int
    old_sha: str


class SyncError(Exception):
    pass


def format_git_error(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout).strip()


def run_git(repo: RepoSpec, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo.path,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise SyncError(f"{repo.name}: unable to run git {' '.join(args)} in {repo.path}: {exc}") from exc

    if check and result.returncode != 0:
        details = format_git_error(result) or f"exit code {result.returncode}"
        raise SyncError(f"{repo.name}: git {' '.join(args)} failed: {details}")
    return result


def require_clean_worktree(repo: RepoSpec) -> None:
    status = run_git(repo, ["status", "--porcelain"]).stdout.strip()
    if status:
        preview = "\n".join(f"    {line}" for line in status.splitlines()[:10])
        raise SyncError(
            f"{repo.name}: worktree is not clean; commit or manually clear these files before syncing:\n"
            f"{preview}"
        )


def parse_counts(repo: RepoSpec) -> tuple[int, int]:
    output = run_git(repo, ["rev-list", "--left-right", "--count", f"HEAD...origin/{MAIN_BRANCH}"]).stdout.strip()
    parts = output.split()
    if len(parts) != 2:
        raise SyncError(f"{repo.name}: unexpected rev-list output: {output}")
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise SyncError(f"{repo.name}: invalid rev-list output: {output}") from exc


def validate_local_repo(repo: RepoSpec) -> None:
    if not repo.path.is_dir():
        raise SyncError(f"{repo.name}: missing repository directory: {repo.path}")

    inside = run_git(repo, ["rev-parse", "--is-inside-work-tree"]).stdout.strip()
    if inside != "true":
        raise SyncError(f"{repo.name}: not a Git worktree: {repo.path}")

    top_level = Path(run_git(repo, ["rev-parse", "--show-toplevel"]).stdout.strip()).resolve()
    if top_level != repo.path.resolve():
        raise SyncError(f"{repo.name}: expected repository root {repo.path}, found {top_level}")

    branch = run_git(repo, ["branch", "--show-current"]).stdout.strip()
    if branch != MAIN_BRANCH:
        raise SyncError(f"{repo.name}: expected branch {MAIN_BRANCH}, found {branch or 'detached HEAD'}")

    origin_url = run_git(repo, ["remote", "get-url", "origin"]).stdout.strip()
    if origin_url != repo.origin_url:
        raise SyncError(f"{repo.name}: expected origin {repo.origin_url}, found {origin_url}")

    require_clean_worktree(repo)


def build_sync_plan(repo: RepoSpec) -> SyncPlan:
    run_git(repo, ["fetch", "origin", MAIN_BRANCH])

    origin = run_git(repo, ["rev-parse", "--verify", f"origin/{MAIN_BRANCH}"], check=False)
    if origin.returncode != 0:
        raise SyncError(f"{repo.name}: origin/{MAIN_BRANCH} does not exist")

    ahead, behind = parse_counts(repo)
    if ahead > 0:
        raise SyncError(
            f"{repo.name}: local branch has {ahead} local commit(s) and is "
            f"{behind} commit(s) behind origin/{MAIN_BRANCH}; manual handling required"
        )

    old_sha = run_git(repo, ["rev-parse", "--short=12", "HEAD"]).stdout.strip()
    return SyncPlan(repo=repo, ahead=ahead, behind=behind, old_sha=old_sha)


def apply_plan(plan: SyncPlan) -> str:
    current_sha = run_git(plan.repo, ["rev-parse", "--short=12", "HEAD"]).stdout.strip()
    if current_sha != plan.old_sha:
        raise SyncError(f"{plan.repo.name}: HEAD changed during sync planning: {plan.old_sha} -> {current_sha}")
    require_clean_worktree(plan.repo)

    if plan.behind == 0:
        return f"{plan.repo.name}: already up to date ({plan.old_sha})"

    run_git(plan.repo, ["merge", "--ff-only", f"origin/{MAIN_BRANCH}"])
    new_sha = run_git(plan.repo, ["rev-parse", "--short=12", "HEAD"]).stdout.strip()
    return f"{plan.repo.name}: updated {plan.old_sha}..{new_sha}"


def verify_synced(repo: RepoSpec) -> None:
    ahead, behind = parse_counts(repo)
    if (ahead, behind) != (0, 0):
        raise SyncError(f"{repo.name}: final sync check failed: ahead={ahead} behind={behind}")
    require_clean_worktree(repo)


def repo_specs() -> list[RepoSpec]:
    anyrule_root = Path(__file__).resolve().parents[1]
    work_root = anyrule_root.parent
    return [
        RepoSpec("anyrule", anyrule_root, "git@github.com:carolcheng520/anyrule.git"),
        RepoSpec("anywhere-rules", work_root / "anywhere-rules", "https://github.com/chikacya/anywhere-rules.git"),
        RepoSpec("Anywhere", work_root / "Anywhere", "https://github.com/NodePassProject/Anywhere.git"),
    ]


def run_sync(repos: list[RepoSpec]) -> int:
    local_errors: list[str] = []
    for repo in repos:
        try:
            validate_local_repo(repo)
        except SyncError as exc:
            local_errors.append(str(exc))

    if local_errors:
        print("Sync blocked before network fetch; no repositories were updated.", file=sys.stderr)
        for error in local_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    plans: list[SyncPlan] = []
    fetch_errors: list[str] = []
    for repo in repos:
        try:
            plans.append(build_sync_plan(repo))
        except SyncError as exc:
            fetch_errors.append(str(exc))

    if fetch_errors:
        print("Sync blocked after fetch; no repository HEADs were updated by this run.", file=sys.stderr)
        for error in fetch_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    try:
        for plan in plans:
            print(apply_plan(plan))
        for repo in repos:
            verify_synced(repo)
    except SyncError as exc:
        print(f"Sync failed: {exc}", file=sys.stderr)
        return 1

    print("All repositories are synced with origin/main.")
    return 0


def run_fixture_git(path: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=path,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        details = format_git_error(result)
        raise SyncError(f"fixture: git {' '.join(args)} failed in {path}: {details}")
    return result.stdout.strip()


def configure_fixture_user(path: Path) -> None:
    run_fixture_git(path, ["config", "user.name", "Sync Script Test"])
    run_fixture_git(path, ["config", "user.email", "sync-script-test@example.com"])


def assert_raises(message: str, fn: Callable[[], object]) -> None:
    try:
        fn()
    except SyncError as exc:
        if message not in str(exc):
            raise SyncError(f"fixture: expected error containing {message!r}, got: {exc}") from exc
        return
    raise SyncError(f"fixture: expected error containing {message!r}")


def run_self_test() -> int:
    root = Path(tempfile.mkdtemp(prefix="sync-github-repos-", dir="/private/tmp"))
    try:
        remote = root / "remote.git"
        seed = root / "seed"
        local = root / "local"

        run_fixture_git(root, ["init", "--bare", str(remote)])
        run_fixture_git(root, ["init", "-b", MAIN_BRANCH, str(seed)])
        configure_fixture_user(seed)
        (seed / "file.txt").write_text("one\n", encoding="utf-8")
        run_fixture_git(seed, ["add", "file.txt"])
        run_fixture_git(seed, ["commit", "-m", "initial"])
        run_fixture_git(seed, ["remote", "add", "origin", str(remote)])
        run_fixture_git(seed, ["push", "-u", "origin", MAIN_BRANCH])
        run_fixture_git(root, ["clone", str(remote), str(local)])

        repo = RepoSpec("fixture", local, str(remote))

        validate_local_repo(repo)
        print("self-test local validation: ok")

        (seed / "file.txt").write_text("two\n", encoding="utf-8")
        run_fixture_git(seed, ["commit", "-am", "second"])
        run_fixture_git(seed, ["push", "origin", MAIN_BRANCH])
        plan = build_sync_plan(repo)
        if (plan.ahead, plan.behind) != (0, 1):
            raise SyncError(f"fixture: expected ahead=0 behind=1, got ahead={plan.ahead} behind={plan.behind}")
        apply_plan(plan)
        verify_synced(repo)
        print("self-test fast-forward: ok")

        (local / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        assert_raises("worktree is not clean", lambda: validate_local_repo(repo))
        print("self-test dirty-worktree block: ok")
        (local / "untracked.txt").unlink()

        configure_fixture_user(local)
        (local / "file.txt").write_text("local\n", encoding="utf-8")
        run_fixture_git(local, ["commit", "-am", "local"])
        assert_raises("local branch has", lambda: build_sync_plan(repo))
        print("self-test local-ahead block: ok")

        (seed / "file.txt").write_text("remote\n", encoding="utf-8")
        run_fixture_git(seed, ["commit", "-am", "remote"])
        run_fixture_git(seed, ["push", "origin", MAIN_BRANCH])
        assert_raises("local branch has", lambda: build_sync_plan(repo))
        ahead, behind = parse_counts(repo)
        if ahead <= 0 or behind <= 0:
            raise SyncError(f"fixture: expected diverged history, got ahead={ahead} behind={behind}")
        print("self-test diverged-history block: ok")

        wrong_origin = RepoSpec("fixture", local, "https://example.invalid/repo.git")
        assert_raises("expected origin", lambda: validate_local_repo(wrong_origin))
        print("self-test origin guard: ok")
    except SyncError as exc:
        print(f"Self-test failed: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(root)

    print("Self-test passed.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run temporary fixture tests without touching the real repositories",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()

    repos = repo_specs()
    return run_sync(repos)


if __name__ == "__main__":
    sys.exit(main())

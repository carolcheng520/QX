---
name: anyrule-maintainer
description: Guarded periodic maintenance for the user's AnyRule/Anywhere repositories. Use when Codex needs to update and publish the maintained AnyRule scripts: refresh rules/wechat.arrs, push it, sync sibling Anywhere source repositories, generate CN direct enhancement rules, push them, and verify GitHub remote parity.
---

# AnyRule Maintainer

## First Use

This skill is distributed inside the `anyrule` repository at `skill/anyrule-maintainer`.

If `$anyrule-maintainer` is not available in Codex after cloning the repository on a new machine, run this from the `anyrule` repository root:

```bash
python3 skill/install_anyrule_maintainer.py
```

The installer creates or updates `${CODEX_HOME:-$HOME/.codex}/skills/anyrule-maintainer` as a symlink to this repo-local skill. It also checks that sibling repositories exist beside `anyrule`: `anywhere-rules` and `Anywhere`.

## Maintenance Workflow

Run the guarded workflow from the `anyrule` repository:

```bash
python3 skill/anyrule-maintainer/scripts/run_anyrule_maintenance.py
```

For a non-mutating environment check, use:

```bash
python3 skill/anyrule-maintainer/scripts/run_anyrule_maintenance.py --check-only
```

If a local upstream mirror such as `Anywhere` has diverged from GitHub and the goal is still to maintain/publish `anyrule`, run the same workflow in fresh temporary clones:

```bash
python3 skill/anyrule-maintainer/scripts/run_anyrule_maintenance.py --isolated
```

For a non-mutating adversarial review of the skill packaging and portability assumptions, use:

```bash
python3 skill/anyrule-maintainer/scripts/run_anyrule_maintenance.py --adversarial-check
```

The workflow is intentionally strict:

- Do not stash, force-push, rebase, or clean files automatically.
- Stop if any repository is on the wrong branch, has the wrong remote, or has unrelated local changes.
- Update WeChat first, push it, and verify GitHub `main` equals local `HEAD`.
- Sync the sibling repositories with `scripts/sync_github_repos.py`.
- Generate CN direct enhancement rules, push them, and verify GitHub `main` equals local `HEAD`.
- Treat no-op generation as success when the worktree and remote are already in sync.
- Use `--isolated` when a disposable upstream mirror is diverged but should not block rule maintenance.

If a sibling mirror is clean and intentionally disposable, it can be reset to GitHub `main` explicitly:

```bash
python3 scripts/sync_github_repos.py --reset-diverged-clean
```

This reset mode is opt-in. The default sync still blocks on local-ahead or diverged history.

## First-Run Lessons

Keep these checks in mind after editing or cloning this skill:

- The official `quick_validate.py` may fail when the active Python lacks `PyYAML`; if so, validate `SKILL.md` frontmatter manually for `name` and `description`, or rerun with a Python that has `PyYAML`.
- The installer should create `${CODEX_HOME:-$HOME/.codex}/skills/anyrule-maintainer` as a symlink to the repo-local skill; restart Codex if the skill list was already loaded.
- `--check-only` intentionally fails while the new `skill/` files are untracked or otherwise dirty. Commit and push the skill before using the live maintenance workflow.
- After cloning on another machine, run the installer once before expecting `$anyrule-maintainer` to trigger automatically.
- When Git reports both ahead and behind counts for an upstream mirror, inspect the diagnostic output before resetting. A `no merge base` message usually means GitHub history was force-updated or replaced.

## Adversarial Review

Run `--adversarial-check` after changing this skill or before publishing it. Treat failures as blockers unless the output explicitly says the failure is expected for an uncommitted local edit.

The review checks that:

- Required skill files are present.
- Skill files are tracked by Git, so another machine can download them.
- The Codex symlink points at the repo-local skill when it exists.
- Skill files do not contain machine-specific absolute paths.
- Existing validator dependency availability is reported explicitly.

## Expected Layout

The scripts use paths relative to the cloned `anyrule` repository, so they work across machines when the repositories share one parent directory:

```text
parent/
├── anyrule/
├── anywhere-rules/
└── Anywhere/
```

Expected remotes:

- `anyrule`: `git@github.com:carolcheng520/anyrule.git`
- `anywhere-rules`: `https://github.com/chikacya/anywhere-rules.git`
- `Anywhere`: `https://github.com/NodePassProject/Anywhere.git`

If a repository is missing, clone it manually into the same parent directory before running the workflow.

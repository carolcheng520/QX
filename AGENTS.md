# AnyRule Maintenance Rules

These instructions apply to this `anyrule` repository.

## Repository Scope

- Keep `README.md` unchanged unless the user explicitly asks to edit it.
- Keep this folder as an independent Git repository that tracks `https://github.com/carolcheng520/anyrule`.
- Make surgical changes only to the rule files needed for the requested task.

## Rule File Headers

- Use English for all comments added to rule files.
- Every maintained `.arrs` and `.amrs` rule file should start with these comment fields:
  - `PURPOSE`: a short English description of what the file is for.
  - `LINK`: the raw GitHub URL for the file on the `main` branch.
  - `SUGGESTED-ACTION`: the intended action in Anywhere.
  - `RULES`: the count of active rule entries in the file.
- For MITM `.amrs` files, also include `COMPANION-FILES` to state whether the rule must be used with any other rule file.
- Update `RULES` whenever adding, removing, or disabling active rule entries.

## Style

- Preserve the existing rule syntax and ordering unless a task requires changing it.
- Do not add speculative domains, IPs, scripts, or abstractions.
- Do not reformat unrelated lines.

---
description: Cut a bastyn-scan release (version-bump PR, then tag) per CONTRIBUTING.md
argument-hint: [version, e.g. 0.1.9]
---

Cut a release of bastyn-scan. `CONTRIBUTING.md`'s "Cutting a release" section
(search for that exact heading) is the source of truth for this process —
re-read it now, fresh, before doing anything below, in case it has changed
since this command was written. This command is a checklist wrapper around
that section, not a replacement for it.

**Target version:** $ARGUMENTS (ask the user if not given — do not guess a
version number).

## Preconditions

- Confirm `main` is green and has nothing release-blocking outstanding.
- Confirm `CHANGELOG.md` already has a filled `## [Unreleased]` section (or a
  filled `## [X.Y.Z]` section from prior work that just needs dating/retitling
  — this repo's history shows both shapes have happened). If `[Unreleased]`
  has nothing in it, stop and ask the user what this release is supposed to
  contain — do not invent changelog content.

## Step 1: open the version-bump PR

Branch from `origin/main` (not from a feature branch), following this repo's
`<github-username>/<description>` branch-naming convention (check
`git branch -r` for examples). Make exactly these changes, per
`CONTRIBUTING.md`:

1. `Cargo.toml`: set `version` under `[workspace.package]` to the new number.
2. Run `cargo build` and commit the resulting `Cargo.lock` (it may be a no-op
   diff if nothing changed).
3. `action.yml`: set the `version` input's `default:` to `v<new-version>`
   (the exact bug `CONTRIBUTING.md` warns this step exists to prevent: a
   stale default silently installs an old binary for anyone who pins the
   Action without naming a version).
4. `CHANGELOG.md`: retitle `## [Unreleased]` as `## [X.Y.Z] - YYYY-MM-DD`
   (today's actual date), add a fresh empty `## [Unreleased]` above it, and
   update the link reference definitions at the bottom of the file (add the
   new version's `releases/tag/vX.Y.Z` link, update the `[Unreleased]` compare
   link to `vX.Y.Z...HEAD`).

Verify the four version numbers agree before opening the PR: `Cargo.toml`,
`Cargo.lock`, `action.yml`'s default, and the `CHANGELOG.md` heading — see
`CONTRIBUTING.md`'s own table of what checks which.

Open the PR against `main` titled `Release X.Y.Z`, doing the bump **and
nothing else** — no unrelated changes riding along. Use `gh pr create`. Model
the body on a previous release PR (`gh pr view <n> --json title,body` on the
most recent one) for tone/structure.

Report the PR URL and stop. **Do not merge it yourself** — the user reviews
and merges the bump PR themselves (or explicitly tells you to merge it).

## Step 2: after the bump PR is merged

This is the part with real, irreversible, externally-visible side effects
(GitHub Release, crates.io publish, Homebrew tap update) — confirm with the
user before running it, even if they already asked you to "release it" in
general terms earlier in the conversation. Show them the exact commands
first.

1. Confirm the merge commit is actually on `main`:
   `git fetch origin main --quiet && git merge-base --is-ancestor <merge-sha> origin/main && echo ok`
2. Confirm no tag for this version already exists:
   `git ls-remote --tags origin | grep v<X.Y.Z>` (must be empty)
3. Tag and push:
   ```
   git tag -a vX.Y.Z <merge-sha> -m "Release X.Y.Z"
   git push origin vX.Y.Z
   ```
   Tag creation on this repo is restricted to admins/the release bot by a
   ruleset — if the push is rejected for permissions, tell the user rather
   than retrying with different credentials or force-pushing.
4. Watch the release workflow: `gh run list --workflow=release.yml --limit 3`.
   Report back once it completes (success or failure) — don't just fire the
   tag and move on silently.

## What NOT to do

- Don't skip re-reading `CONTRIBUTING.md` — this command intentionally
  doesn't inline its full rationale, so treat that file as authoritative if
  anything here looks out of date.
- Don't push the tag without explicit confirmation, even if this command was
  invoked with clear intent to release — tagging is the one step in this
  whole process that actually publishes something publicly and cannot be
  quietly undone.
- Don't bundle unrelated changes into the bump PR.
- Don't write changelog entries with internal review-process wording,
  benchmark specifics, or references to other repos/tools — this project's
  changelog and PR text stay neutral and technical (state what changed, not
  who found it or how it was validated).

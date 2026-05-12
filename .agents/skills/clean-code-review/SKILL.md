---
name: clean-code-review
description: Review a PR or local branch through the Clean Code lens defined in `dev_docs/clean_code.md`. Use when the user runs `/clean-code-review`, asks for a "Clean Code" or "Bob Martin" review of a PR or branch, or wants this specific review lens applied. One of a family of single-lens code-review skills. Emits observations only on changed lines, with severity tags (`strong-suggestion` / `suggestion` / `nit`). Does not post GitHub comments.
---

# Clean Code review

Single-lens code review. The lens is defined in `dev_docs/clean_code.md`. Other lenses (security, performance, accessibility, etc.) are sibling skills and run independently.

## When to invoke

- User runs `/clean-code-review` (with or without an argument).
- User asks for a Clean Code review, "Bob Martin review", or "review through Clean Code".
- User wants this lens applied to a PR (URL or number) or to the current local branch.

Do **not** invoke for generic "please review this PR" — that's a different skill.

## Inputs

- **No argument** → current local branch.
  - Resolve the merge-base: `git merge-base HEAD origin/main`. If `origin/main` doesn't exist, try `origin/HEAD`, then `main`.
  - Diff: `git diff <merge-base>`. This compares the working tree to the merge-base and therefore includes committed, staged, and unstaged changes — i.e. everything the developer has touched locally vs. main. This is intentional.
- **Argument = PR number or URL** (e.g. `123`, `#123`, `https://github.com/elastic/kibana/pull/123`).
  - Extract the number from the URL if needed.
  - Diff: `gh pr diff <number>`. Works for live and merged PRs.
  - For full-file context, fetch the head ref view: `gh pr view <number> --json headRefName,headRefOid` and, if needed, read files via `gh api repos/{owner}/{repo}/contents/{path}?ref=<headRefOid>`. For the common case where the PR is the current branch, reading from disk is enough.

If neither path produces a diff, exit with: `No diff to review. Aborting.`

## Steps

1. **Resolve target and get diff.** Print one line: `Reviewing <target> — <N> changed files (<M> excluded).`
2. **Filter files.** Drop these from observation candidates (still allowed in context if useful):
   - Lockfiles: `package-lock.json`, `yarn.lock`, `*-lock.yaml`, `Cargo.lock`
   - Snapshots: `**/*.snap`
   - Translations: `**/translations/*.json`, `**/locales/*.json`
   - Assets/binaries: `*.png`, `*.jpg`, `*.jpeg`, `*.gif`, `*.svg`, `*.ico`, `*.woff`, `*.woff2`, `*.ttf`, `*.eot`
   - Vendored/built: `**/node_modules/**`, `**/target/**`, `**/build/**`, `**/dist/**`
   - Bazel: `BUILD.bazel`, `*.bazel`
   - Files whose first ~10 lines contain `AUTO-GENERATED`, `@generated`, or `DO NOT EDIT`.
3. **Cap at 50 non-excluded files.** Count is over the *post-filter* set. If more, take the first 50 by alphabetic path and remember the skipped count for the trailer.
4. **Load `dev_docs/clean_code.md` once.** Read it relative to the repo root. If missing, exit with: `Clean Code doc not found at dev_docs/clean_code.md. Aborting.`
5. **For each file in the working set:**
   - Read the whole file from disk (or from the PR ref for non-local targets) for context.
   - Walk the diff hunks; the candidate lines for observations are the `+` and modified lines only.
   - For each candidate line, evaluate against the principles in `dev_docs/clean_code.md` §§1–10.
   - Skip ambiguous cases. Only emit a violation when you can name the specific principle (§N.N) and the fix would be obvious to a reviewer.
6. **Emit the report.** Format per `OUTPUT.md`.

## Diff-scope rule (non-negotiable)

- **Candidates for observation = diff lines only.** Lines the developer didn't touch are never the subject of an observation, even if they're worse than the diff itself.
- **Whole-file context is for understanding only**: how a symbol is used, what type a variable is, whether a function is on a public contract. Use that context to *decide* whether a diff line is a clear violation. Don't move the observation's line number outside the diff.

## Calibration

- **Bias toward silence.** If you can't cite a specific principle by section number, don't emit.
- **One observation per (line, principle).** No duplicates. If a line violates two principles, pick the strongest and skip the other.
- **Don't suggest extracts** that contradict `AGENTS.md` ("three similar lines beats a premature abstraction"). A long function that does one thing and reads top-down is fine.
- **Don't restate the linter / type checker.** If ESLint or `tsc` already flags it (no-empty, no-unused-vars, etc.), leave it alone.
- **Auto-demote conflicts.** If the principle appears in `clean_code.md` Appendix B, set severity to `nit` and prefix the **Observation** with `(conflicts with CLAUDE.md — see Appendix B)`. If the Appendix B row says `rule not emitted`, suppress entirely.
- **No moralising.** State the violation in one sentence and stop.
- **Test files.** Apply all principles. Use §8 (Tests) where applicable.

## Out of scope

- Posting comments to GitHub. The skill prints the report to chat; the user decides what to do with it.
- Other review lenses (security, performance, accessibility, i18n, etc.).
- Refactor proposals beyond the diff.
- Replacing or duplicating `/review` (which is broader and lens-agnostic).

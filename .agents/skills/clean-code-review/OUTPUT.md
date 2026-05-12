# Default output format

Use this when invoking the `clean-code-review` skill directly. Callers that supply their own output format (CI bots, macroscope configs, etc.) should follow those instructions instead.

Output is plain Markdown to chat. Do **not** post to GitHub.

## Header

One line:

```
Clean Code review for <target> — <X> observations across <Y> files.
```

`<target>` is either `branch` (local) or `PR #<n>`. If `X` is zero, emit only:

```
No Clean Code observations.
```

…and stop. Don't add a trailer or empty sections.

## Body

Group observations by severity, most severe first: `strong-suggestion` → `suggestion` → `nit`. Use the severity as the section heading (`### strong-suggestion`, etc.). Within each severity, order by file path, then ascending line number. Omit any severity section with zero observations.

For each observation:

- **Principle:** `§N.N <short title>` — link as `dev_docs/clean_code.md#NN-anchor`
- **Line:** `<path>:<line>`
- **Observation:** one sentence. State the violation; don't moralise.
- **Suggestion:** one sentence or one short code line. Omit if not obvious or if it would conflict with `AGENTS.md`.

If the principle is in `clean_code.md` Appendix B (Conflicts), set severity to `nit` and prefix **Observation** with `(conflicts with CLAUDE.md — see Appendix B)`.

## Trailer

One line, only if non-zero:

```
Files skipped — excluded: <N>, over 50-file cap: <N>.
```

Omit when both counts are zero.

## Example

```
Clean Code review for branch — 3 observations across 2 files.

### strong-suggestion

- **Principle:** §2.5 No hidden side effects (dev_docs/clean_code.md#25-no-hidden-side-effects)
  **Line:** src/platform/plugins/shared/alerting/server/rules_client/rules_client.ts:142
  **Observation:** `validateRule` writes the audit log; the name implies a pure check.
  **Suggestion:** split — `validateRule` returns the result, `recordRuleValidation` writes the audit row.

### suggestion

- **Principle:** §2.3 Few arguments (dev_docs/clean_code.md#23-few-arguments--options-object-after-two)
  **Line:** x-pack/plugins/security_solution/public/detections/components/actions.tsx:67
  **Observation:** five positional args, two of them booleans.
  **Suggestion:** options object — easy to swap booleans by accident.

### nit

- **Principle:** §3.5 JSDoc on public entry points (dev_docs/clean_code.md#35-jsdoc-on-public-packageplugin-entry-points)
  **Line:** x-pack/plugins/security_solution/public/detections/components/actions.tsx:201
  **Observation:** (conflicts with CLAUDE.md — see Appendix B) new exported helper `runAction` has no JSDoc on the plugin contract.
```

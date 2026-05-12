# Clean Code in Kibana

An adapted, cherry-picked version of Robert C. Martin's *Clean Code* (2008) for this codebase. We keep the principles that survive in a modern TypeScript/React monorepo and drop or rewrite the ones that don't. The goal is to give human reviewers and the `clean-code-review` skill a shared, citable reference.

## Stance

- **Prefer X, but Y is acceptable when there's a reason.** Nothing here is a hard rule.
- **Conflict-resolution order** when guidance disagrees:
  1. Written rules — lint, `AGENTS.md` / `.claude/CLAUDE.md`, and Kibana style guides.
  2. This doc.
- Unwritten local conventions don't override these principles. If a violation here matches an entrenched local pattern, the principle still applies — a reviewer may justify the deviation in PR review, but the skill will still raise it.
- When a principle here conflicts with (1), the Kibana rule wins. Such principles are listed in [Appendix B](#appendix-b--conflicts-with-claudemd--lint) and the review skill auto-demotes them.

## How to read this doc

Each principle has the same shape:

- **Prefer**: the rule, with permitted relaxations stated in plain prose where they apply.
- **Why**: the underlying reason. Useful for judging edge cases.
- **In Kibana**: a short TypeScript example in our idiom.
- **Severity**: how the review skill should classify a clear violation.
- **Adapted**: whether and how we changed Martin's original.
- **Conflicts with**: any rule in `AGENTS.md` / lint this principle bumps into.

Severities:

- **strong-suggestion** — a clear smell with consensus that it's worth fixing.
- **suggestion** — defensible default; reasonable people may disagree.
- **nit** — small, often stylistic, or contradicted by stricter Kibana guidance.

The skill only reports clear violations and stays silent when it can't name a specific principle. Diff lines only; whole-file context is used for understanding, not for emitting observations outside the diff.

---

## 1. Names

### 1.1 Use intention-revealing names

- **Prefer** names that say *why* something exists and *what* it does. Short names are fine in tight local scope (a 5-line lambda) when the type makes intent obvious.
- **Why**: a name that needs a comment should be a better name. Renaming is cheap; misreading is not.
- **In Kibana**:
  ```ts
  // avoid
  const d = Date.now() - rule.t;

  // prefer
  const msSinceLastRun = Date.now() - rule.lastRunAt;
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

### 1.2 Avoid disinformation

- **Prefer** names that don't lie about type, plurality, or behavior.
- **Why**: `accountList` for a `Set` mis-sets reader expectations; `getDashboard` that returns an array trips the convention (`get` = one by id, `find` = many by query).
- **In Kibana**:
  ```ts
  // avoid: it's a Set, not a list
  const accountList = new Set<string>();

  // avoid: `get` suggests a single result; this queries and returns many
  const getDashboard = async (spaceId: string): Promise<Dashboard[]> =>
    soClient.find({ type: 'dashboard', spaceId });

  // prefer
  const accounts = new Set<string>();
  const findDashboards = async (spaceId: string): Promise<Dashboard[]> =>
    soClient.find({ type: 'dashboard', spaceId });
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

### 1.3 Make meaningful distinctions

- **Prefer** distinct names for distinct things. Reject noise words (`Info`, `Data`, `Manager`, `Helper`) that don't disambiguate.
- **In Kibana**:
  ```ts
  // avoid: which one carries the rule?
  function createRule(rule: Rule, ruleInfo: RuleInfo, ruleData: RuleData) {}

  // prefer
  function createRule(rule: Rule, source: RuleSource, owner: User) {}
  ```
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 1.4 No type or scope encoding

- **Prefer** plain names. TypeScript and your editor already know the type.
- **In Kibana**:
  ```ts
  // avoid
  interface IRuleService {}
  const sRule = ruleStore.get(id);
  const m_started = Date.now();

  // prefer
  interface RuleService {}
  const rule = ruleStore.get(id);
  const startedAt = Date.now();
  ```
- **Severity**: nit
- **Adapted**: no
- **Conflicts with**: none (lint catches `I`-prefix in most areas)

### 1.5 Types are nouns; functions are verbs

- **Prefer** noun names for types/classes, verb phrases for functions, and `is`/`has`-style noun phrases for booleans.
- **Severity**: nit
- **Adapted**: no
- **Conflicts with**: none

### 1.6 One word per concept

- **Prefer** one verb per operation, used consistently across a module/package: `fetch` *or* `get` *or* `retrieve`, not all three.
- **In Kibana**: if a package exposes `fetchRule`, don't add `getRuleById` alongside it for the same thing.
- **Severity**: nit
- **Adapted**: no
- **Conflicts with**: none

---

## 2. Functions

### 2.1 Do one thing

- **Prefer** functions that do one identifiable thing — gather, transform, or commit a side effect — not all three. Keeping them together is fine when the function is short and splitting would create indirection without insight.
- **Why**: single-purpose functions are easier to name, test, and reuse. They produce diffs that read.
- **In Kibana**:
  ```ts
  // avoid: gather + transform + commit, each step with real substance
  const updateRuleSchedule = async (id: string, newIntervalMs: number) => {
    const raw = await soClient.get<RawRule>('alert', id);
    if (!raw) throw new Error(`Rule ${id} not found`);

    const schedule = newIntervalMs < 1000
      ? { interval: '1s' }
      : { interval: `${Math.floor(newIntervalMs / 1000)}s` };
    const next = {
      ...raw.attributes,
      schedule,
      updatedAt: new Date().toISOString(),
      revision: (raw.attributes.revision ?? 0) + 1,
    };

    await soClient.update('alert', id, next);
    if (raw.attributes.scheduled) {
      await taskManager.schedule(id, schedule);
    }
    return next;
  };

  // prefer: each helper earns its name; the orchestrator reads top-down
  const updateRuleSchedule = async (id: string, newIntervalMs: number) => {
    const current = await fetchRule(id);
    const next = withUpdatedSchedule(current, newIntervalMs);
    await persistRuleSchedule(id, next);
    return next;
  };
  ```
- **Severity**: suggestion
- **Adapted**: yes — we keep the single-purpose intent and drop Martin's strict size rule (see [Appendix A](#appendix-a--what-we-dont-adopt-and-why)).
- **Conflicts with**: tension with `AGENTS.md` "three similar lines beats a premature abstraction". Don't extract until the helper has a name that adds insight on its own.

### 2.2 One level of abstraction per function

- **Prefer** function bodies that operate at a single level of abstraction. Mixing `await soClient.update(...)` with a string-manipulation loop is two levels.
- **In Kibana**:
  ```ts
  // avoid: high-level orchestration interleaved with low-level shaping
  const buildAndSaveDashboard = async (panels: Panel[]) => {
    const title = panels.map((p) => p.name).join(' / ');
    const out = { title, panels, version: '1' };
    await soClient.create('dashboard', out);
  };

  // prefer
  const buildAndSaveDashboard = async (panels: Panel[]) => {
    const dashboard = buildDashboard(panels);
    await soClient.create('dashboard', dashboard);
  };
  ```
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 2.3 Few arguments — options object after two

- **Prefer** 0–2 positional arguments. Beyond that, take a typed options object.
- **In Kibana**:
  ```ts
  // avoid: positional booleans, easy to swap by accident
  scheduleRule(ruleId, true, false, 30);

  // prefer
  scheduleRule(ruleId, { enabled: true, runImmediately: false, intervalSec: 30 });
  ```
- **Severity**: suggestion
- **Adapted**: minor — Martin says ≤3; we apply "options object after two", matching the prevailing Kibana convention.
- **Conflicts with**: none

### 2.4 No flag arguments

- **Prefer** splitting flag-driven functions in two, or expressing the choice as a union/enum.
- **In Kibana**:
  ```ts
  // avoid: positional boolean flag
  renderPanel(panel, /* isEditing */ true);

  // prefer: split when there are only two modes
  renderEditablePanel(panel);

  // or, when there are more than two modes, use a typed union
  type PanelMode = 'view' | 'edit' | 'preview';
  renderPanel(panel, mode);
  ```
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 2.5 No hidden side effects

- **Prefer** functions whose name announces their effects. If `validateUser` also updates `lastSeen`, the name is lying — rename or split.
- **In Kibana**:
  ```ts
  // avoid: `get` implies a read; the body writes on the miss path
  const getRunsIndex = async (es: ElasticsearchClient) => {
    const exists = await es.indices.exists({ index: RUNS_INDEX });
    if (!exists) await es.indices.create({ index: RUNS_INDEX, body: mapping });
    return RUNS_INDEX;
  };

  // prefer: name announces the effect
  const ensureRunsIndex = async (es: ElasticsearchClient) => {
    const exists = await es.indices.exists({ index: RUNS_INDEX });
    if (!exists) await es.indices.create({ index: RUNS_INDEX, body: mapping });
    return RUNS_INDEX;
  };
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

---

## 3. Comments

### 3.1 Comments don't compensate for bad code

- **Prefer** rewriting unclear code over annotating it.
- **In Kibana**:
  ```ts
  // avoid: comment explains a compound condition
  // allow edit only if the user is an admin, or they own the rule and it's enabled
  if (user.role === 'admin' || (rule.ownerId === user.id && rule.enabled)) {
    return renderEditForm(rule);
  }

  // prefer: the predicate names itself; comment becomes redundant
  const canEditRule = (user: User, rule: Rule) =>
    user.role === 'admin' || (rule.ownerId === user.id && rule.enabled);

  if (canEditRule(user, rule)) {
    return renderEditForm(rule);
  }
  ```
- **Severity**: suggestion
- **Adapted**: no — aligned with `AGENTS.md`
- **Conflicts with**: none

### 3.2 Explain WHY, not WHAT

- **Prefer** comments that capture a non-obvious constraint, invariant, workaround tied to a specific bug, or surprising behavior. Writing no comment is usually best when names already carry the meaning.
- **Why**: "what" comments rot when the code changes and the comment doesn't. "Why" comments encode information not derivable from the code.
- **In Kibana**:
  ```ts
  // avoid: restates the code
  // increment retry count
  attempt += 1;

  // avoid: history that belongs in git
  // 2024-08: changed from 5s to 30s after the on-call paged for SDH-1234

  // prefer: explains a constraint the reader can't derive
  // Task Manager schedules with second precision; sub-second values silently round up.
  const interval = Math.max(intervalMs, 1000);
  ```
- **Severity**: nit
- **Adapted**: yes — softened. `AGENTS.md` defaults to *no* comments and we follow it; this rule only fires when a comment actively restates or misleads.
- **Conflicts with**: `AGENTS.md` "Default to writing no comments" is stricter than Martin.

### 3.3 Delete commented-out code

- **Prefer** deleting. Git remembers. Commented blocks rot and confuse readers about whether the code is "almost used".
- **In Kibana**:
  ```ts
  // avoid
  // const old = await soClient.get('alert', id);
  // const next = { ...old, schedule: { interval: '5m' } };
  const current = await fetchRule(id);
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

### 3.4 No journal, attribution, or redundant comments

- **Prefer** the PR description and `git blame` for history. Don't write `// added by X`, `// 2024-08: fix for SDH-1234`, or restate-the-line comments.
- **Severity**: nit
- **Adapted**: no — aligned with `AGENTS.md`
- **Conflicts with**: none

### 3.5 JSDoc on public package/plugin entry points

- **Prefer** brief JSDoc on exports from a package's `index.ts` or a plugin's `setup`/`start` contract. Internal helpers don't need it.
- **In Kibana**:
  ```ts
  /**
   * Returns the singleton rules client for the current plugin context.
   * Throws if called before `start()`.
   */
  export const getRulesClient = (): RulesClient => { /* ... */ };
  ```
- **Severity**: nit
- **Adapted**: yes — Martin applies JSDoc liberally; we limit it to public entry points.
- **Conflicts with**: tension with `AGENTS.md` "default to no comments". Public-API doc comments are widely accepted as part of the contract.

---

## 4. Formatting

Prettier and ESLint own the literal layout. The remaining humane rules:

- **Vertical openness between concepts**: blank line between groups of related lines (variable setup → transformation → return).
- **Dense within a concept**: don't break up lines that read as one thought.
- **Variables declared near use**, not at the top of the function unless used throughout.
- **Caller above callee** when both live in the same file. Soft preference — module systems make this less load-bearing than in single-file Java.

The review skill does not emit formatting observations; those belong to tooling.

---

## 5. Data vs. structures

### 5.1 Prefer plain data for cross-module payloads

- **Prefer** `interface`/`type` over classes when the value just carries data across a contract boundary. Easier to serialise, narrow, and version.
- **In Kibana**: plugin `setup`/`start` contracts are objects of functions and data, not class instances.
- **Severity**: suggestion
- **Adapted**: yes — TS reframing of Martin's "data structure vs. object" duality.
- **Conflicts with**: none

### 5.2 Behavior lives with the object that owns the state

- **Prefer** methods on the object whose state they read/mutate. Free functions are fine where there's no shared state — most TS modules look like this.
- **Severity**: suggestion
- **Adapted**: yes — softened. TS modules already give us composition without classes.
- **Conflicts with**: none

### 5.3 Discriminated unions over optional grab-bags

- **Prefer** a discriminated union when an object's shape depends on a mode/state. **Avoid** types where half the fields are optional because they apply only to one variant.
- **In Kibana**:
  ```ts
  // avoid
  interface RuleAction {
    type: 'email' | 'webhook';
    to?: string;       // only for email
    url?: string;      // only for webhook
    headers?: Record<string, string>; // only for webhook
  }

  // prefer
  type RuleAction =
    | { type: 'email'; to: string }
    | { type: 'webhook'; url: string; headers: Record<string, string> };
  ```
- **Severity**: strong-suggestion
- **Adapted**: yes — TS-native; Martin doesn't address it directly.
- **Conflicts with**: none

### 5.4 Law of Demeter (adapted)

- **Prefer** not reaching through chains of fetched objects (`a.getB().getC().doThing()`). Ask `a` for what you need. Traversing a known data structure (parsed JSON, config) is fine — Demeter applies to objects that hide internals, not pure data.
- **Severity**: nit
- **Adapted**: yes — narrowed to behavioral objects.
- **Conflicts with**: none

---

## 6. Error handling

### 6.1 Throw for unexpected, return a typed result for expected

- **Prefer** `throw` for invariant violations the caller can't reasonably handle. Return a typed value (`{ ok: false; reason }`, `Either`, `undefined`) for expected outcomes.
- **In Kibana**: route handlers convert thrown errors to HTTP responses at the edge; expected validation failures are better as values than exceptions.
- **Severity**: suggestion
- **Adapted**: yes — TS-shaped restatement of "exceptions vs. return codes".
- **Conflicts with**: none

### 6.2 Don't catch what you can't handle

- **Prefer** letting an error bubble to a layer that can do something useful with it. Catch-and-rethrow at the call site is usually noise.
- **In Kibana**:
  ```ts
  // avoid: adds nothing
  try {
    await soClient.update(/* ... */);
  } catch (e) {
    logger.error(e);
    throw e;
  }
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

### 6.3 No empty or swallowing catches

- **Prefer** logging or rethrowing. Never `catch (e) {}`. If a failure is genuinely ignorable, narrow the catch and say why.
- **In Kibana**:
  ```ts
  // avoid
  try { await sendNotification(); } catch {}

  // prefer
  try {
    await sendNotification();
  } catch (e) {
    logger.warn(`notification failed: ${e.message}`); // best-effort send
  }
  ```
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none

### 6.4 Prefer `undefined` over `null`

- **Prefer** `undefined` for "no value" inside Kibana TypeScript. Use `null` when a contract, upstream API, or Elasticsearch response mandates it.
- **Severity**: nit
- **Adapted**: yes — TS-specific restatement of Martin's "don't return/pass null".
- **Conflicts with**: none

### 6.5 Wrap third-party errors at the boundary

- **Prefer** translating errors from external libraries into domain errors at the edge of your plugin/package, so internal code doesn't depend on the third party's error shape.
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

---

## 7. Boundaries

### 7.1 Wrap third-party APIs at the plugin/package edge

- **Prefer** a thin adapter for any third-party SDK (HTTP client, cloud SDK, parser). Internal code calls the adapter, not the library.
- **Why**: easier to mock, easier to swap, easier to evolve the library version.
- **In Kibana**: see how plugins consume Elasticsearch via `core.elasticsearch` rather than instantiating clients directly.
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 7.2 Don't leak external types past your contract

- **Prefer** exporting your own types from a plugin's contract. Don't make consumers depend on a transitive third-party type.
- **In Kibana**:
  ```ts
  // avoid: consumers now depend on the @elastic/elasticsearch version
  export interface RulesPluginStart {
    runRule: (req: SearchRequest) => Promise<SearchResponse>;
  }

  // prefer
  export interface RulesPluginStart {
    runRule: (req: RuleRunRequest) => Promise<RuleRunResult>;
  }
  ```
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 7.3 Learning tests for fuzzy external behavior

- **Prefer** writing small tests that pin down how a third party actually behaves, then keeping them in CI so behavior changes show up early.
- **Severity**: nit
- **Adapted**: no
- **Conflicts with**: none

---

## 8. Tests

### 8.1 F.I.R.S.T

- **Prefer** tests that are **F**ast (milliseconds for unit), **I**ndependent (no shared state, any-order runnable), **R**epeatable (no env/network coupling for unit), **S**elf-validating (assertions, not console output), and **T**imely (written with the code they test).
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 8.2 One concept per test

- **Prefer** each `it`/`test` asserting a single observable behavior. Long tests with assertions on unrelated paths are hard to interpret on failure.
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 8.3 Readable assertions, no magic constants

- **Prefer** named expected values. Use builders/factories for shared shapes instead of repeating large inline objects across tests.
- **Severity**: nit
- **Adapted**: no
- **Conflicts with**: none

### 8.4 Don't test implementation details

- **Prefer** asserting behavior (return values, observable side effects). Avoid asserting which internal helper was called or how often, unless the call itself is the contract (e.g. retries).
- **Severity**: strong-suggestion
- **Adapted**: yes — TS/Jest restatement.
- **Conflicts with**: none

---

## 9. Modules

This section replaces Martin's "Classes" chapter. Kibana's unit of cohesion is the package or plugin, not the class.

### 9.1 Single, articulable purpose per package/plugin

- **Prefer** packages and plugins you can describe in one sentence ("manages rule execution", "renders the dashboard sidebar"). When the description needs "and", suspect a split.
- **In Kibana**: this is reflected in `kibana.jsonc` ownership and the module group rules.
- **Severity**: strong-suggestion for new packages; suggestion for existing changes that drift the purpose.
- **Adapted**: yes — Kibana-specific; replaces Martin's class-level SRP.
- **Conflicts with**: none

### 9.2 Small, explicit public surface

- **Prefer** a focused entry point (single `index.ts`) exporting only what consumers need. Keep helpers internal.
- **In Kibana**: packages forbid deep imports — the entry point *is* the contract.
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 9.3 No circular plugin dependencies

- **Prefer** unidirectional plugin graphs. If two plugins need shared types, extract a third package.
- **Severity**: strong-suggestion
- **Adapted**: no
- **Conflicts with**: none — Kibana's plugin loader enforces this too.

### 9.4 Export only what's needed

- **Prefer** keeping symbols un-exported until a consumer needs them. Each export is a future maintenance cost.
- **Severity**: suggestion
- **Adapted**: no
- **Conflicts with**: none

### 9.5 Server plugin entry must not eagerly load `plugin.ts`

- **Prefer** `import type` (and `export type`) for types from `./plugin` in `server/index.ts`. Load the implementation lazily inside the async `plugin` initializer: `await import('./plugin')`.
- **Why**: prevents `plugin.ts` from being parsed and executed when the plugin is disabled.
- **In Kibana**: enforced by `@kbn/eslint/no_sync_import_from_plugin` and documented in `AGENTS.md`.
- **Severity**: strong-suggestion
- **Adapted**: yes — Kibana-specific.
- **Conflicts with**: none — aligned with `AGENTS.md` and the linter.

---

## 10. Code smells (curated)

Pattern-level prompts, not line-level rules. The review skill may cite these alongside the underlying principle (e.g. "this looks like a god contract — see §9.2").

- **Rigidity**: a small change requires touching many files.
- **Fragility**: a change in one module breaks an unrelated one.
- **Opacity**: a section requires reading many other files to understand.
- **Needless complexity**: speculative generality, abstractions with one user.
- **Dead code**: unreachable branches, unused exports, commented-out blocks.
- **Inconsistency**: the same concept handled differently in different places in the same diff.
- **God contract**: a plugin `setup`/`start` contract with dozens of methods of unrelated purpose.
- **Long parameter lists**: see §2.3 — at three or more, move to an options object.
- **Misplaced responsibility**: logic that belongs in a different layer (e.g. UI doing validation the server also does).

---

## Appendix A — What we don't adopt and why

### Strict function size targets

Martin: "20 lines max; 4 is better." We don't enforce a line count. **Why**: extracting trivial helpers in TS fragments the call site without improving understanding. `AGENTS.md` explicitly prefers "three similar lines beats a premature abstraction". We keep the spirit (do one thing, one level of abstraction) without the letter.

### "Extract till you drop"

Martin pushes recursive extraction as a discovery mechanism. We don't. **Why**: it encourages micro-functions that exist for one caller, trading one cognitive load (longer body) for another (jumping around the file).

### The full OO "Classes" chapter

Martin's chapter assumes Java-style OO with inheritance hierarchies and member-state-driven cohesion. **Why**: most Kibana code is module-organized, not class-organized. We replace this chapter with §9 (Modules), keeping the cohesion intent and dropping the OO-specific mechanics.

### Java concurrency

Out of scope for a Node/TS runtime.

### JUnit-specific test plumbing

We use Jest and Playwright. Mocks-as-classes, `@Before`/`@After` style, etc. don't translate.

### "Newspaper" code-ordering metaphor

A weak preference in TS — module systems and editor "find usages" make it less load-bearing than in single-file Java classes. Caller-above-callee ordering is fine when natural, not when contrived.

---

## Appendix B — Conflicts with `AGENTS.md` / lint

When a Clean Code principle conflicts with `AGENTS.md` / `.claude/CLAUDE.md` or a lint rule, **the Kibana rule wins**. The `clean-code-review` skill auto-demotes such observations to `nit` and prefixes them with `(conflicts with CLAUDE.md — see Appendix B)`. Rules marked "rule not emitted" are suppressed entirely.

| # | Clean Code says | Kibana says | We follow | Severity in review |
|---|---|---|---|---|
| B.1 | Functions should be 4–20 lines max | Three similar lines beats a premature abstraction (`AGENTS.md`) | Kibana | rule not emitted |
| B.2 | Extract aggressively to reveal intent | Don't add abstractions beyond what the task requires (`AGENTS.md`) | Kibana | rule not emitted |
| B.3 | Use JSDoc on most exported functions (§3.5) | Default to no comments; only WHY when non-obvious (`AGENTS.md`) | Kibana | nit |
| B.4 | "Why" comments are encouraged on subtle code (§3.2) | Default to no comments unless the WHY is non-obvious (`AGENTS.md`) | Kibana | nit (only fires when comment is misleading or redundant) |
| B.5 | Classes are the primary unit of cohesion | Packages/plugins are; classes are one tool among many | Kibana | n/a — replaced by §9 |

Add rows here as new conflicts surface in practice.

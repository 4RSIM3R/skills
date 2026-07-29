---
name: ux-code-audit
description: Perform a static UX audit of any frontend or app codebase by traversing the code, without running the app or opening a browser. Use this whenever the user asks for a UX audit, UX review, design review, accessibility check, flow map, or "check my UI/UX", and no dev server or browser tool is available or wanted. Also use when the user asks to map pages/components/flows, find duplicated or inconsistent components, or review forms, loading/error/empty states, and navigation in code. Works with any language or framework — the skill discovers the stack from the repo itself. Also use to resume or inspect a previous audit if a `.ux-audit/` directory exists in the repo. Do not use for audits that require a running app (rendered layout, visual contrast, live interaction); recommend a browser-based review for those instead.
---

# UX Code Audit (Static, Stack-Agnostic)

Audit the UX quality of any codebase that has a user interface, purely by reading the code. The core method: **discover the stack, map every page and component, trace each user flow, then evaluate against UX principles and produce prioritized recommendations.** Never assume a specific framework; derive everything from the repo.

## Working artifacts (write as you go — mandatory)

All intermediate work is dumped to a `.ux-audit/` directory at the repo root so a human (or a later agent session) can inspect what was examined, what was concluded, and why. **Write each artifact at the end of its phase step, not at the end of the audit.** If the session dies mid-audit, the artifacts are the recovery point.

```
.ux-audit/
├── 00-audit-brief.md           # Phase 0.5: user's answers to intake questions + stated assumptions
├── 00-conventions-profile.md   # Phase 0 output
├── 01-screen-inventory.md      # Phase 1A
├── 02-component-graph.md       # Phase 1B
├── 03-flows/<screen-id>.md     # Phase 1C, one file per traced screen
├── 04-findings-log.md          # Phase 2, append-only as findings are confirmed
└── audit-journal.md            # running log, see below
```

**audit-journal.md** is an append-only reasoning log. After each meaningful unit of work, append a dated entry: what was just examined (files/dirs), what was concluded, what was ruled out and why, open questions, and what comes next. Keep entries to 3-6 lines. This is the "what was the agent thinking" record — candidate findings that turned out to be false positives belong here (with the reason they were dismissed), not silently dropped.

**Resume behavior:** at the start of any audit, check for an existing `.ux-audit/`. If present, read `audit-journal.md` and the phase artifacts, tell the user where the previous run stopped, and continue from there instead of restarting. Only restart from scratch if the user asks or the codebase has changed enough that the map is stale (note which, in the journal).

Suggest adding `.ux-audit/` to the VCS ignore file, but leave the choice to the user (committing it can be useful for team review).

## Phase 0 — Discover the stack

Do not bring assumptions. Infer from the repository itself:

1. Read manifest/config files at the root (dependency manifests, build configs, lockfiles) and note languages by file extension distribution.
2. Identify, in the project's own terms:
   - How **screens/pages/routes** are defined (file-based routing, a router config, a navigation controller, templates, whatever the codebase uses)
   - How **reusable UI components** are defined and where they live
   - How **styling** is done and whether a design system exists (tokens, theme files, shared primitives)
   - How **data fetching / mutations / async work** is done
   - How **forms and validation** are handled
   - How **navigation between screens** happens
   - How **text/copy** is managed (inline strings vs a localization system)
3. Write the "conventions profile" — the canonical way this codebase does each of the above — to `.ux-audit/00-conventions-profile.md`. Every later check compares code against *this profile*, not against any external framework's best practices.
4. If the repo is large, ask the user which screens/flows matter most; otherwise default to entry/auth, the main screen, and the primary create/edit/transaction flows. Record the chosen scope in the journal.

## Phase 0.5 — Audit brief: ask what the code cannot tell you

After discovery, some things needed for a good UX judgment are simply not in the code. **Ask the user about anything still unclear, in ONE batch of questions, before starting Phase 1.** Never ask something the repo already answered (asking about the color system when a theme file exists wastes the user's time; asking which of two conflicting color systems is canonical does not).

Cover whichever of these the code left ambiguous:

- **Persona / target users.** Who uses this, and how tech-savvy are they? (An internal admin tool for power users and a consumer app for first-time users get judged very differently — density, jargon, confirmation friction.)
- **Primary jobs.** The 1-3 tasks a user must complete successfully; these flows get the deepest tracing and the strictest severity.
- **Visual and brand intent.** Preferred colors/palette, tone (playful vs formal), any brand guideline or reference product. Without this, consistency findings can only say "these two disagree", not "this one is wrong".
- **Platform and device priorities.** Mobile-first or desktop-first, minimum screen sizes, touch vs pointer, offline expectations.
- **Accessibility bar.** Any explicit target (e.g. a WCAG level, a legal requirement) or "best effort".
- **Market and locale.** Target market, language(s), currency/date conventions.
- **Known pain points.** What the user or their users already complain about — audit those areas first.
- **Anything else the discovery raised.** Conflicting conventions, ambiguous auth boundaries, screens whose purpose could not be inferred.

Keep the batch short: only questions whose answers would actually change a finding or its severity, ideally 4-8, as a numbered list so the user can answer inline. If the user answers partially or says "just proceed", proceed — but write explicit assumptions for every unanswered question. Record all answers and assumptions in `.ux-audit/00-audit-brief.md`, and tag findings that depend on an assumption so they are easy to re-check if the assumption was wrong.

## Phase 1 — Map pages, components, and flows

This map is the backbone of the audit. Build three artifacts:

**A. Screen inventory** → `.ux-audit/01-screen-inventory.md`. Every screen/page/route: identifier, source file, purpose (one line, inferred from code), auth-gated or public, reachable from where.

**B. Component graph** → `.ux-audit/02-component-graph.md`. Every reusable component: name, file, what it renders (one line), where it is used (usage count), and its inputs/outputs (props, parameters, events, callbacks). Flag while building:
- Components used **once** (candidate to inline) and components used **nowhere** (dead code)
- Components that are **near-duplicates**: similar name, similar structure, or copy-pasted bodies with small edits. Compare structure, not just names. These are prime findings — duplicates drift apart and create inconsistent UX.
- Components that reimplement something the project's own design system already provides
- Inputs passed through many layers untouched (deep pass-through), and components with very large input surfaces (a smell for unclear responsibility)

**C. Flow map** → `.ux-audit/03-flows/<screen-id>.md`, one file per priority screen, written immediately after tracing that screen. Trace the user's path through the code:
- Entry: how the user lands here, what loads, what they see first
- Actions: every interactive element and what its handler actually does (follow the call chain: validation → async call → state change → feedback → navigation)
- Exits: where the user can go next, including failure paths
- Side effects: what is persisted, sent, or mutated

Render flows as short step lists or diagrams. A flow map that reveals "the error path goes nowhere" or "this action gives no feedback" *is* the audit finding.

## Phase 2 — Evaluate

Judge each mapped flow and component against UX principles, expressed generically. Adapt detection to whatever the stack turned out to be. These categories are a floor, not a ceiling — report anything the map reveals that would hurt the user, whether or not it is listed here. Append each **confirmed** finding to `.ux-audit/04-findings-log.md` the moment it is verified (with file:line and evidence); log dismissed candidates in the journal with the dismissal reason.

**State coverage.** Every async operation should account for four states: in-progress, failure, empty result, success. Trace each one from the flow map and name which states are missing. Actions that can be triggered twice while pending (double-submit) are High severity.

**Forms and input.** Labels tied to inputs; input types/keyboards appropriate to the data; validation feedback shown near the field and at the right moment; input preserved on failure; clear success signal; destructive or irreversible submissions guarded.

**Feedback.** Every user action produces perceivable feedback; long operations show progress; errors tell the user what happened and what to do next; ephemeral notices (toasts and the like) are not the only record of an error.

**Navigation and orientation.** Every screen has a title/identity; there is a not-found/fallback path; back/exit behavior is safe (unsaved-work guards on long inputs); the user can always tell where they are and how to leave.

**Consistency.** Compare everything against the Phase 0 conventions profile: rogue one-off components where a shared one exists, hardcoded style values where tokens exist, mixed patterns for the same job (two form approaches, two fetch approaches), inconsistent wording for the same action across screens.

**Duplication and structure.** Report the near-duplicates, dead components, and reimplementations found in Phase 1B, each with a concrete recommendation: merge, extract, delete, or adopt the existing primitive. Show which files would consolidate.

**Accessibility semantics.** Interactive elements are real interactive elements (or carry equivalent semantics), images/icons have text alternatives, structure uses the platform's semantic constructs, keyboard/assistive paths exist for every pointer path, focus is managed on screen changes and overlays. Express findings in the platform's own vocabulary.

**Adaptivity.** Layouts tolerate different sizes/orientations per the platform's mechanism; fixed dimensions and overflow-prone constructs are flagged; media declares dimensions where the platform needs it to avoid layout shift.

**Copy and locale.** Language consistency; hardcoded user-facing strings when a localization system exists; locale-appropriate dates, numbers, currency for the product's market.

## Phase 3 — Report

Write `ux-audit-report.md` at the repo root (or where the user asks). The report is assembled **from** the `.ux-audit/` artifacts — it should contain no claim that is not backed by an artifact entry:

1. **Summary** — overall state, top 3 issues, and what is genuinely good (always name strengths; an all-negative report gets ignored).
2. **The map** — screen inventory, component graph highlights (link to the full artifact files for detail), and the flow maps for priority screens.
3. **Findings by severity** with stable IDs (UX-001…): Blocker (breaks a flow or excludes users), High (significant friction or error-proneness), Medium (inconsistency, duplication, missing polish), Low (hygiene). Each finding: `file:line`, what the code does, why it hurts the user in one concrete sentence, and a suggested fix — as a snippet when under ~10 lines, otherwise as a plan.
4. **Recommendations** — open-ended, beyond defect-fixing: consolidation opportunities from the component graph, flow simplifications, convention gaps worth codifying.
5. **Not covered** — state plainly that static analysis cannot verify rendered layout, real contrast, motion, or live interaction, and recommend a browser/device pass before major releases.

Close the journal with a final entry: audit complete, scope covered, anything deliberately skipped.

## Rules

- Never report a pattern-match hit without reading its context. False accusations destroy trust in the whole report.
- Never cite a "best practice" from a framework the project does not use. The reference standard is the project's own conventions profile, the audit brief (persona, brand, platform, locale), and universal UX principles — in that order of specificity.
- Ask clarifying questions once, as the Phase 0.5 batch. Mid-audit questions are allowed only when a genuine blocker appears; otherwise note the uncertainty in the journal and keep going on a stated assumption.
- Prefer few, verified, high-impact findings; cap the report at ~25 and roll the long tail into one recurring-patterns note (full list stays in the findings log).
- Write artifacts incrementally, per phase step — never hold the whole audit in memory and dump at the end.
- Do not modify source files during the audit; the only writes are inside `.ux-audit/` and the final report. Offer fixes as a follow-up, one severity tier at a time, starting with Blockers, staying strictly within the project's existing conventions.